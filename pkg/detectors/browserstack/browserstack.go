package browserstack

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"hub-cloud.browserstack.com", "accessKey", "\"access_Key\":", "ACCESS_KEY", "key", "browserstackKey", "BS_AUTHKEY", "BROWSERSTACK_ACCESS_KEY"}) + `\b([0-9a-zA-Z]{20})\b`)
	userPat = regexp.MustCompile(detectors.PrefixRegex([]string{"hub-cloud.browserstack.com", "userName", "\"username\":", "USER_NAME", "user", "browserstackUser", "BS_USERNAME", "BROWSERSTACK_USERNAME"}) + `\b([a-zA-Z\d]{3,18}[._-]?[a-zA-Z\d]{6,11})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"browserstack"}
}

// FromData will find and optionally verify BrowserStack secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)
	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	userMatches := userPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		for _, userMatch := range userMatches {
			if len(userMatch) != 2 {
				continue
			}

			resUserMatch := strings.TrimSpace(userMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_BrowserStack,
				Raw:          []byte(resMatch),
				RawV2:        []byte(resMatch + resUserMatch),
			}

			if verify {
				client := s.client
				if client == nil {
					client = defaultClient
				}

				req, err := http.NewRequestWithContext(ctx, "GET", "https://www.browserstack.com/automate/plan.json", nil)
				if err != nil {
					s1.VerificationError = err
				} else {
					req.Header.Add("Content-Type", "application/json")
					req.SetBasicAuth(resUserMatch, resMatch)
					res, err := client.Do(req)
					if err != nil {
						s1.VerificationError = err
					} else {
						defer res.Body.Close()
						if res.StatusCode >= 200 && res.StatusCode < 300 {
							s1.Verified = true
						} else if res.StatusCode != 401 {
							s1.VerificationError = fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
						}
					}
				}
			}

			// This function will check false positives for common test words, but also it will make sure the key appears 'random' enough to be a real key.
			if !s1.Verified && detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, true) {
				continue
			}
			results = append(results, s1)
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_BrowserStack
}
