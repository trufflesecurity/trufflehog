package quickmetrics

import (
	"bytes"
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
	client = common.SaneHttpClient()
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"quickmetrics"}) + `\b([a-zA-Z0-9_-]{22})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("quickmetrics")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_QuickMetrics,
			Raw:          resMatch,
		}

		if verify {
			payload := bytes.NewBuffer([]byte(`[{"name":"api.response.time","dimension":null,"values":[[1568319841,12.4],[1568319856,9.3],[1568319860,234],[1568319863,3.2]]},{"name":"click.color","dimension":"green","values":[[1568319841,1],[1568319856,1],[1568319860,1],[1568319863,1]]}]`))
			req, err := http.NewRequestWithContext(ctx, "POST", "https://qckm.io/list", payload)
			if err != nil {
				continue
			}
			req.Header.Add("Content-Type", "application/json")
			req.Header.Add("x-qm-key", string(resMatch))
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

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_QuickMetrics
}
