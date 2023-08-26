package appcues

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

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	keyPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"appcues"}) + `\b([a-z0-9-]{36})\b`)
	userPat = regexp.MustCompile(detectors.PrefixRegex([]string{"appcues"}) + `\b([a-z0-9-]{39})\b`)
	idPat   = regexp.MustCompile(detectors.PrefixRegex([]string{"appcues"}) + `\b([0-9]{5})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("appcues")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {

	keyMatches := keyPat.FindAllSubmatch(data, -1)
	userMatches := userPat.FindAllSubmatch(data, -1)
	idMatches := idPat.FindAllSubmatch(data, -1)

	for _, match := range keyMatches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])

		for _, userMatch := range userMatches {
			if len(userMatch) != 2 {
				continue
			}

			resUserMatch := bytes.TrimSpace(userMatch[1])

			for _, idMatch := range idMatches {
				if len(idMatch) != 2 {
					continue
				}

				resIdMatch := bytes.TrimSpace(idMatch[1])

				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_Appcues,
					Raw:          resMatch,
					RawV2:        append(resMatch, resUserMatch...),
				}

				if verify {
					req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://api.appcues.com/v2/accounts/%s/flows", string(resIdMatch)), nil)
					if err != nil {
						continue
					}
					req.SetBasicAuth(string(resUserMatch), string(resMatch))
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
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Appcues
}
