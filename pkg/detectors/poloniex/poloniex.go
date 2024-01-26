package poloniex

import (
	"context"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	regexp "github.com/wasilibs/go-re2"
	"net/http"
	"net/url"
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
	keyPat    = regexp.MustCompile(detectors.PrefixRegex([]string{"poloniex"}) + `\b([0-9A-Z]{8}-[0-9A-Z]{8}-[0-9A-Z]{8}-[0-9A-Z]{8})\b`)
	secretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"poloniex"}) + `\b([0-9a-f]{128})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"poloniex"}
}

// FromData will find and optionally verify Poloniex secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	secretMatches := secretPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
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
				DetectorType: detectorspb.DetectorType_Poloniex,
				Raw:          []byte(resSecretMatch),
				RawV2:        []byte(resMatch + resSecretMatch),
			}

			if verify {

				timestamp := strconv.FormatInt(time.Now().Unix()*1000, 10)

				payload := url.Values{}
				payload.Add("command", "returnBalances")
				payload.Add("nonce", timestamp)

				signature := getPoloniexSignature(resSecretMatch, payload.Encode())

				req, err := http.NewRequestWithContext(ctx, "POST", "https://poloniex.com/tradingApi", strings.NewReader(payload.Encode()))
				if err != nil {
					continue
				}
				req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
				req.Header.Add("Key", resMatch)
				req.Header.Add("Sign", signature)
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

						if detectors.IsKnownFalsePositive(resSecretMatch, detectors.DefaultFalsePositives, true) {
							continue
						}
					}
				}
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func getPoloniexSignature(secret string, payload string) string {
	mac := hmac.New(sha512.New, []byte(secret))
	mac.Write([]byte(payload))
	macsum := mac.Sum(nil)
	return hex.EncodeToString(macsum)
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Poloniex
}
