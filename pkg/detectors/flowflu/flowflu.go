package flowflu

import (
	"bytes"
	"context"
	"fmt"
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

	keyPat     = regexp.MustCompile(detectors.PrefixRegex([]string{"flowflu"}) + (`\b([a-zA-Z0-9]{51})\b`))
	accountPat = regexp.MustCompile(detectors.PrefixRegex([]string{"flowflu", "account"}) + (`\b([a-zA-Z0-9]{4,30})\b`))
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("flowflu")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllSubmatch(data, -1)
	accountMatches := accountPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])

		for _, accountMatch := range accountMatches {
			if len(accountMatch) != 2 {
				continue
			}

			resAccount := bytes.TrimSpace(accountMatch[1])

			r := detectors.Result{
				DetectorType: detectorspb.DetectorType_FlowFlu,
				Raw:          resMatch,
			}

			if verify {
				req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://%s.flowlu.com/api/v1/module/crm/lead/list?api_key=%s", string(resAccount), string(resMatch)), nil)
				if err != nil {
					continue
				}
				res, err := client.Do(req)
				if err != nil {
					continue
				}

				if res.StatusCode >= 200 && res.StatusCode < 300 {
					defer res.Body.Close()

					if bytes.Contains(resMatch, []byte(`total_result`)) {
						r.Verified = true
					} else {
						r.Verified = false
					}
				} else {
					if detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, true) {
						continue
					}
				}
			}

			results = append(results, r)
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_FlowFlu
}
