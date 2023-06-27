package semaphore

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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"semaphore"}) + `\b([0-9a-z]{32})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"semaphore.co"}
}

// FromData will find and optionally verify Semaphore secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		if !detectors.HasDigit(resMatch) {
			continue
		}

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Semaphore,
			Raw:          []byte(resMatch),
		}

		if verify {
			req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://api.semaphore.co/api/v4/account?apikey=%s", resMatch), nil)
			if err != nil {
				continue
			}
			req.Header.Add("Accept", "application/vnd.semaphore+json; version=3")
			res, err := client.Do(req)
			if err == nil {
				defer res.Body.Close()
				bodyBytes, err := io.ReadAll(res.Body)
				if err != nil {
					continue
				}
				body := string(bodyBytes)
				if res.StatusCode >= 200 && res.StatusCode < 300 && strings.Contains(body, "account_id") {
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

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Semaphore
}
