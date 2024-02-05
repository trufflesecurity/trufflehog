package kraken

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	regexp "github.com/wasilibs/go-re2"
	"io"
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
	// Bounds have been removed because there are some cases that tokens have trailing frontslash(/) or plus sign (+)
	keyPat     = regexp.MustCompile(detectors.PrefixRegex([]string{"kraken"}) + `\b([0-9A-Za-z\/\+=]{56}[ "'\r\n]{1})`)
	privKeyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"kraken"}) + `\b([0-9A-Za-z\/\+=]{86,88}[ "'\r\n]{1})`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"kraken"}
}

// FromData will find and optionally verify Kraken secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	privKeyMatches := privKeyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		for _, privKeyMatch := range privKeyMatches {
			if len(privKeyMatch) != 2 {
				continue
			}
			resPrivKeyMatch := strings.TrimSpace(privKeyMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Kraken,
				Raw:          []byte(resMatch),
				RawV2:        []byte(resMatch + resPrivKeyMatch),
			}

			if verify {

				// Increasing 64-bit integer, for each request that is made with a particular API key.
				apiNonce := strconv.FormatInt(time.Now().Unix(), 10)

				payload := url.Values{}
				payload.Add("nonce", apiNonce)

				b64DecodedSecret, _ := base64.StdEncoding.DecodeString(resPrivKeyMatch)
				signature := getKrakenSignature("/0/private/Balance", payload, b64DecodedSecret)

				req, err := http.NewRequestWithContext(ctx, "POST", "https://api.kraken.com/0/private/Balance", strings.NewReader(payload.Encode()))
				if err != nil {
					continue
				}
				req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
				req.Header.Add("API-Key", resMatch)
				req.Header.Add("API-Sign", signature)

				res, err := client.Do(req)
				if err == nil {
					defer res.Body.Close()
					out, _ := io.ReadAll(res.Body)
					if !strings.Contains(string(out), "Invalid key") {
						s1.Verified = true
					} else {
						// This function will check false positives for common test words, but also it will make sure the key appears 'random' enough to be a real key
						if detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, true) {
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

// Code from https://docs.kraken.com/rest/#section/Authentication/Headers-and-Signature
func getKrakenSignature(url_path string, values url.Values, secret []byte) string {

	sha := sha256.New()
	sha.Write([]byte(values.Get("nonce") + values.Encode()))
	shasum := sha.Sum(nil)

	mac := hmac.New(sha512.New, secret)
	mac.Write(append([]byte(url_path), shasum...))
	macsum := mac.Sum(nil)
	return base64.StdEncoding.EncodeToString(macsum)
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Kraken
}
