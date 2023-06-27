package cexio

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
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
	keyPat    = regexp.MustCompile(detectors.PrefixRegex([]string{"cexio", "cex.io"}) + `\b([0-9A-Za-z]{24,27})\b`)
	secretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"cexio", "cex.io"}) + `\b([0-9A-Za-z]{24,27})\b`)
	userIdPat = regexp.MustCompile(detectors.PrefixRegex([]string{"cexio", "cex.io"}) + `\b([a-z]{2}[0-9]{9})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"cexio", "cex.io"}
}

// FromData will find and optionally verify CexIO secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	keyMatches := keyPat.FindAllStringSubmatch(dataStr, -1)
	secretMatches := secretPat.FindAllStringSubmatch(dataStr, -1)
	userIdMatches := userIdPat.FindAllStringSubmatch(dataStr, -1)

	for _, userIdMatch := range userIdMatches {
		if len(userIdMatch) != 2 {
			continue
		}
		resUserIdMatch := strings.TrimSpace(userIdMatch[1])

		for _, keyMatch := range keyMatches {
			if len(keyMatch) != 2 {
				continue
			}
			resKeyMatch := strings.TrimSpace(keyMatch[1])

			for _, secretMatch := range secretMatches {
				if len(secretMatch) != 2 {
					continue
				}
				resSecretMatch := strings.TrimSpace(secretMatch[1])

				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_CexIO,
					Raw:          []byte(resKeyMatch),
					RawV2:        []byte(resUserIdMatch + resSecretMatch),
				}

				if verify {

					timestamp := strconv.FormatInt(time.Now().Unix()*1000, 10)

					signature := getCexIOPassphrase(resSecretMatch, resKeyMatch, timestamp, resUserIdMatch)

					payload := url.Values{}
					payload.Add("key", resKeyMatch)
					payload.Add("signature", signature)
					payload.Add("nonce", timestamp)

					req, err := http.NewRequestWithContext(ctx, "POST", "https://cex.io/api/balance/", strings.NewReader(payload.Encode()))
					if err != nil {
						continue
					}
					req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
					res, err := client.Do(req)
					if err == nil {
						defer res.Body.Close()

						body, err := io.ReadAll(res.Body)
						if err != nil {
							continue
						}
						bodyString := string(body)
						validResponse := strings.Contains(bodyString, `timestamp`)

						var responseObject Response
						if err := json.Unmarshal(body, &responseObject); err != nil {
							continue
						}

						if res.StatusCode >= 200 && res.StatusCode < 300 && validResponse {
							s1.Verified = true
						} else {
							// This function will check false positives for common test words, but also it will make sure the key appears 'random' enough to be a real key.
							if detectors.IsKnownFalsePositive(resUserIdMatch, detectors.DefaultFalsePositives, true) {
								continue
							}

							if detectors.IsKnownFalsePositive(resKeyMatch, detectors.DefaultFalsePositives, true) {
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
	}

	return results, nil
}

type Response struct {
	Error string `json:"error"`
}

func getCexIOPassphrase(apiSecret string, apiKey string, nonce string, userId string) string {

	msg := nonce + userId + apiKey
	mac := hmac.New(sha256.New, []byte(apiSecret))
	mac.Write([]byte(msg))
	macsum := mac.Sum(nil)
	return strings.ToUpper(hex.EncodeToString(macsum))
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_CexIO
}
