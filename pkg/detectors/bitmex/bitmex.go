package bitmex

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
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
	keyPat    = regexp.MustCompile(detectors.PrefixRegex([]string{"bitmex"}) + `([ \r\n]{1}[0-9a-zA-Z\-\_]{24}[ \r\n]{1})`)
	secretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"bitmex"}) + `([ \r\n]{1}[0-9a-zA-Z\-\_]{48}[ \r\n]{1})`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"bitmex"}
}

// FromData will find and optionally verify Bitmex secrets in a given set of bytes.
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
				DetectorType: detectorspb.DetectorType_Bitmex,
				Raw:          []byte(resSecretMatch),
				RawV2:        []byte(resMatch + resSecretMatch),
			}

			if verify {

				timestamp := strconv.FormatInt(time.Now().Unix()+5, 10)
				action := "GET"
				path := "/api/v1/user"
				payload := url.Values{}

				signature := getBitmexSignature(timestamp, resSecretMatch, action, path, payload.Encode())

				req, err := http.NewRequestWithContext(ctx, action, "https://www.bitmex.com"+path, strings.NewReader(payload.Encode()))
				if err != nil {
					continue
				}
				req.Header.Add("api-expires", timestamp)
				req.Header.Add("api-key", resMatch)
				req.Header.Add("api-signature", signature)
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

func getBitmexSignature(timeStamp string, secret string, action string, path string, payload string) string {

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(action + path + timeStamp + payload))
	macsum := mac.Sum(nil)
	return hex.EncodeToString(macsum)
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Bitmex
}
