package formbucket

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"formbucket"}) + `\b([0-9A-Za-z]{1,}.[0-9A-Za-z]{1,}\.[0-9A-Z-a-z\-_]{1,})`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"formbucket"}
}

// FromData will find and optionally verify FormBucket secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_FormBucket,
			Raw:          []byte(resMatch),
		}

		if verify {
			req, err := http.NewRequestWithContext(ctx, "GET", "https://www.formbucket.com/v1/profile", nil)
			if err != nil {
				continue
			}
			req.Header.Add("Accept", "application/json")
			req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", resMatch))
			res, err := client.Do(req)
			if err == nil {
				defer res.Body.Close()
				body, errBody := io.ReadAll(res.Body)
				if errBody != nil {
					continue
				}
				bodyString := string(body)
				validResponse := strings.Contains(bodyString, `created_on`)
				defer res.Body.Close()
				if errBody == nil {
					if res.StatusCode >= 200 && res.StatusCode < 300 && validResponse {
						s1.Verified = true
					} else {
						// This function will check false positives for common test words, but also it will make sure the key appears 'random' enough to be a real key.
						if detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, true) {
							continue
						}
					}
				}
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

type Response struct {
	Anonymous bool `json:"anonymous"`
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_FormBucket
}
