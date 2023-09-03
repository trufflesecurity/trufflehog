package pivotaltracker

import (
	"context"
	"net/http"
	"regexp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

var _ detectors.Detector = (*Scanner)(nil)

var (
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"pivotal"}) + `([a-z0-9]{32})`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("pivotal")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {

	matches := keyPat.FindAllSubmatch(data, -1)

	for _, match := range matches {

		if len(match) != 2 {
			continue
		}

		token := match[1]

		s := detectors.Result{
			DetectorType: detectorspb.DetectorType_PivotalTracker,
			Raw:          token,
		}

		if verify {
			client := common.SaneHttpClient()
			req, err := http.NewRequestWithContext(ctx, "GET", "https://www.pivotaltracker.com/services/v5/me", nil)
			if err != nil {
				continue
			}
			req.Header.Add("Content-Type", "application/json; charset=utf-8")
			req.Header.Add("X-TrackerToken", string(token))
			res, err := client.Do(req)
			if err == nil {
				res.Body.Close()

				if res.StatusCode >= 200 && res.StatusCode < 300 {
					s.Verified = true
				}
			}
		}

		if !s.Verified && detectors.IsKnownFalsePositive(s.Raw, detectors.DefaultFalsePositives, true) {
			continue
		}

		results = append(results, s)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_PivotalTracker
}
