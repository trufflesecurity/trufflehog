package dyspatch

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"dyspatch"}) + `\b([A-Za-z0-9]{52})\b`)
)

// Keywords are used for pre-filtering chunks.
func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("dyspatch")}
}

// FromData will find and optionally verify Dyspatch secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Dyspatch,
			Raw:          resMatch,
		}

		if verify {
			req, err := http.NewRequestWithContext(ctx, "GET", "https://api.dyspatch.io/templates", nil)
			if err != nil {
				continue
			}
			req.Header.Add("Accept", "application/vnd.dyspatch.2020.11+json")
			req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", resMatch))
			res, err := client.Do(req)
			if err == nil {
				defer res.Body.Close()
				bodyBytes, err := io.ReadAll(res.Body)
				if err != nil {
					continue
				}
				limitedUsage := bytes.Contains(bodyBytes, []byte("limited_usage"))
				data := bytes.Contains(bodyBytes, []byte("data"))

				validResponse := limitedUsage || data

				if validResponse {
					s1.Verified = true
				} else {
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
	return detectorspb.DetectorType_Dyspatch
}
