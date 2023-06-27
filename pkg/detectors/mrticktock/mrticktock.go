package mrticktock

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
	emailPat = regexp.MustCompile(`\b([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.[a-z]+)\b`)
	pwordPat = regexp.MustCompile(detectors.PrefixRegex([]string{"mrticktock"}) + `\b([a-zA-Z0-9!=@#$%()_^]{1,50})`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"mrticktock"}
}

// FromData will find and optionally verify Mrticktock secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := emailPat.FindAllStringSubmatch(dataStr, -1)
	passwordMatches := pwordPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		for _, passwordMatch := range passwordMatches {
			if len(passwordMatch) != 2 {
				continue
			}
			resPassword := strings.TrimSpace(passwordMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Mrticktock,
				Raw:          []byte(resMatch),
			}

			if verify {
				payload := strings.NewReader(fmt.Sprintf(`email=%s&password=%s`, resMatch, resPassword))
				req, err := http.NewRequestWithContext(ctx, "POST", "https://mrticktock.com/app/api/is_timer_active", payload)
				if err != nil {
					continue
				}
				req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
				res, err := client.Do(req)
				if err == nil {
					defer res.Body.Close()
					bodyBytes, err := io.ReadAll(res.Body)
					if err != nil {
						continue
					}
					body := string(bodyBytes)
					if res.StatusCode >= 200 && res.StatusCode < 300 && strings.Contains(body, `"errors":[]`) {
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
	}
	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Mrticktock
}
