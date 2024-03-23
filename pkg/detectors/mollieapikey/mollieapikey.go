package mollieapikey

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

type Scanner struct {
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClientTimeOut(5 * time.Second)

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"mollie"}) + `\b(test_[0-9A-Za-z]{30})\b`)
)

func (s Scanner) Keywords() []string {
	return []string{"mollie"}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_MollieAPIKey,
			Raw:          []byte(resMatch),
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}
			req, err := http.NewRequestWithContext(ctx, "GET", "https://api.mollie.com/v2/customers", nil)
			if err != nil {
				s1.VerificationError = err
			} else {
				req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", resMatch))
				res, err := client.Do(req)
				if err != nil {
					s1.VerificationError = err
				} else {
					defer res.Body.Close()

					// Removing the prefix 'test' first from the token since it is detected as false positive
					resMatch = strings.TrimPrefix(resMatch, "test")

					if res.StatusCode >= 200 && res.StatusCode < 300 {
						s1.Verified = true
					} else if res.StatusCode != 401 {
						s1.VerificationError = fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
					}
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
	return detectorspb.DetectorType_MollieAPIKey
}
