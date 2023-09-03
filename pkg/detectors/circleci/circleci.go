package circleci

import (
	"context"
	"net/http"
	"regexp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"circle"}) + `([a-fA-F0-9]{40})`)
)

// Keywords are used for efficiently pre-filtering chunks.
func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("circle")}
}

// FromData will find and optionally verify Circle secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		token := match[1]

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Circle,
			Raw:          token,
		}

		if verify {
			client := common.SaneHttpClient()
			req, err := http.NewRequestWithContext(ctx, "GET", "https://circleci.com/api/v2/me", nil)
			if err != nil {
				continue
			}
			req.Header.Add("Accept", "application/json;")
			req.Header.Add("Circle-Token", string(token))
			res, err := client.Do(req)
			if err == nil && res != nil {
				defer res.Body.Close()
				if res.StatusCode >= 200 && res.StatusCode < 300 {
					s1.Verified = true
				}
			}
		}

		if !s1.Verified {
			if detectors.IsKnownFalsePositive(token, detectors.DefaultFalsePositives, true) {
				continue
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Circle
}
