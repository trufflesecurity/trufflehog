package cloudelements

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

	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"cloudelements"}) + `\b([a-zA-Z0-9]{43})\b`)
	orgPat = regexp.MustCompile(detectors.PrefixRegex([]string{"cloudelements"}) + `\b([a-z0-9]{32})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("cloudelements")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {

	matches := keyPat.FindAllSubmatch(data, -1)
	orgMatches := orgPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])

		for _, orgMatch := range orgMatches {
			if len(orgMatch) != 2 {
				continue
			}

			resOrgMatch := bytes.TrimSpace(orgMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_CloudElements,
				Raw:          resMatch,
				RawV2:        append(resMatch, resOrgMatch...),
			}

			if verify {
				req, err := http.NewRequestWithContext(ctx, "GET", "https://staging.cloud-elements.com/elements/api-v2/accounts", nil)
				if err != nil {
					continue
				}
				req.Header.Add("Authorization", fmt.Sprintf("User %s, Organization %s", string(resMatch), string(resOrgMatch)))
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
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_CloudElements
}
