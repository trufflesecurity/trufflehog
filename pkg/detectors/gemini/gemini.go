package gemini

import (
	"context"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat    = regexp.MustCompile(detectors.PrefixRegex([]string{"gemini"}) + `\b([0-9Aa-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`)
	secretPat = regexp.MustCompile(`[^A-Za-z0-9+\/]{0,1}([A-Za-z0-9+\/]{40})[^A-Za-z0-9+\/]{0,1}`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"gemini"}
}

// FromData will find and optionally verify Gemini secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	idMatches := keyPat.FindAllStringSubmatch(dataStr, -1)
	secretMatches := secretPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range idMatches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		for _, secretMatch := range secretMatches {
			if len(secretMatch) != 2 {
				continue
			}
			resSecretMatch := strings.TrimSpace(secretMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Gemini,
				Raw:          []byte(resMatch),
				RawV2:        []byte(resMatch + resSecretMatch),
			}

			if verify {
				data := url.Values{}
				data.Set("request", "/v1/account")
				data.Set("nonce", strconv.FormatInt(time.Now().Unix(), 10))
				req, err := http.NewRequestWithContext(ctx, "POST", "https://api.gemini.com/v1/account", nil)
				if err != nil {
					continue
				}

				b64 := base64.StdEncoding.EncodeToString([]byte(data.Encode()))
				signature := constructSignature(b64, resSecretMatch)

				req.Header = http.Header{
					"Content-Type":       {"text/plain"},
					"Content-Length":     {"0"},
					"X-GEMINI-APIKEY":    {resMatch},
					"X-GEMINI-PAYLOAD":   {b64},
					"X-GEMINI-SIGNATURE": {signature},
					"Cache-Control":      {"no-cache"},
				}
				res, err := client.Do(req)
				if err == nil {
					defer res.Body.Close()
					if res.StatusCode >= 200 && res.StatusCode < 300 {
						s1.Verified = true
					} else {
						// This function will check false positives for common test words, but also it will make sure the key appears 'random' enough to be a real key.
						if detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, true) {
							continue
						}
					}
				}
			}
			results = append(results, s1)
		}
	}

	return detectors.CleanResults(results), nil
}

func constructSignature(key string, resSecretMatch string) string {
	h := hmac.New(sha512.New384, []byte(key))
	h.Write([]byte(resSecretMatch))
	signature := base64.StdEncoding.EncodeToString(h.Sum(nil))
	return signature
}
