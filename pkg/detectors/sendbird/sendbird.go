package sendbird

import (
	"context"
	"encoding/json"
	"fmt"
	regexp "github.com/wasilibs/go-re2"
	"net/http"
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
	keyPat   = regexp.MustCompile(detectors.PrefixRegex([]string{"sendbird"}) + `\b([0-9a-f]{40})\b`)
	appIdPat = regexp.MustCompile(detectors.PrefixRegex([]string{"sendbird"}) + `\b([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})\b`)
)

type userResp struct {
	Code int `json:"code"`
}

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"sendbird"}
}

// FromData will find and optionally verify Sendbird secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	appIdMatches := appIdPat.FindAllStringSubmatch(dataStr, -1)

	for _, appIdMatch := range appIdMatches {
		if len(appIdMatch) != 2 {
			continue
		}
		resAppIdMatch := strings.TrimSpace(appIdMatch[1])

		for _, match := range matches {
			if len(match) != 2 {
				continue
			}
			resMatch := strings.TrimSpace(match[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Sendbird,
				Raw:          []byte(resMatch),
			}
			s1.ExtraData = map[string]string{
				"rotation_guide": "https://howtorotate.com/docs/tutorials/sendbird/",
			}

			if verify {
				req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://api-%s.sendbird.com/v3/users", resAppIdMatch), nil)
				if err != nil {
					continue
				}
				req.Header.Add("Api-Token", resMatch)

				client := s.client
				if client == nil {
					client = defaultClient
				}

				res, err := client.Do(req)
				if err == nil {
					defer res.Body.Close()
					if res.StatusCode >= 200 && res.StatusCode < 300 {
						s1.Verified = true
					} else if res.StatusCode == 400 { // Sendbird returns 400 for all errors
						var userResp userResp
						err := json.NewDecoder(res.Body).Decode(&userResp)
						if err != nil {
							err = fmt.Errorf("error decoding json response body: %w", err)
							s1.SetVerificationError(err, resMatch)
						} else if userResp.Code != 400401 {
							// https://sendbird.com/docs/chat/platform-api/v3/error-codes
							// Sendbird always includes its own error codes with 400 responses
							// 400401 (InvalidApiToken) is the only one that indicates a bad token
							err = fmt.Errorf("unexpected response code: %d", userResp.Code)
							s1.SetVerificationError(err, resMatch)
						}
					} else {
						err = fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
						s1.SetVerificationError(err, resMatch)
					}
				} else {
					s1.SetVerificationError(err, resMatch)
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
	return detectorspb.DetectorType_Sendbird
}
