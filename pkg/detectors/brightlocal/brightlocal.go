package brightlocal

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

// Ensure the Scanner satisfies the interface at compile time
type Scanner struct {
	client *http.Client
}

var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClientTimeOut(5 * time.Second)

	//Make sure that your group is surrounded in boundry characters such as below to reduce false positives
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"brightlocal"}) + `\b([a-f0-9]{40})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"brightlocal"}
}

// FromData will find and optionally verify Brightlocal secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Brightlocal,
			Raw:          []byte(resMatch),
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}
			payload := strings.NewReader(fmt.Sprintf("api-key=%s", resMatch))
			req, err := http.NewRequestWithContext(ctx, "POST", "https://tools.brightlocal.com/seo-tools/api/v4/batch", payload)
			if err != nil {
				s1.VerificationError = err
			} else {
				req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
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

					//This function will check false positives for common test words, but also it will make sure the key appears 'random' enough to be a real key

				}
			}
		}
		if !s1.Verified && detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, true) {
			continue
		}

		results = append(results, s1)
	}

	return detectors.CleanResults(results), nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Brightlocal
}
