package npmtokenv2

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
var _ detectors.Versioner = (*Scanner)(nil)

func (s Scanner) Version() int { return 2 }

var (
	client = common.SaneHttpClient()
	keyPat = regexp.MustCompile(`(npm_[0-9a-zA-Z]{36})`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("npm_")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}

		resMatch := match[1]
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_NpmToken,
			Raw:          resMatch,
		}

		if verify {
			req, err := http.NewRequestWithContext(ctx, "GET", "https://registry.npmjs.org/-/whoami", nil)
			if err != nil {
				continue
			}
			req.Header.Add("Authorization", "Bearer "+string(resMatch))
			res, err := client.Do(req)
			if err == nil {
				defer res.Body.Close()
				if res.StatusCode >= 200 && res.StatusCode < 300 {
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

	return
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_NpmToken
}
