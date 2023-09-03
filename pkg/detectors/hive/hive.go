package hive

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
	idPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"hive"}) + `\b([0-9A-Za-z]{17})\b`)
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"hive"}) + `\b([0-9a-z]{32})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("hive")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	idMatches := idPat.FindAllSubmatch(data, -1)
	keyMatches := keyPat.FindAllSubmatch(data, -1)

	for _, match := range idMatches {
		if len(match) != 2 {
			continue
		}

		idMatch := bytes.TrimSpace(match[1])

		for _, match := range keyMatches {
			if len(match) != 2 {
				continue
			}

			keyMatch := bytes.TrimSpace(match[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Hive,
				Raw:          idMatch,
			}

			if verify {
				req, err := http.NewRequestWithContext(ctx, "GET", "https://app.hive.com/api/v1/testcredentials?user_id="+string(idMatch)+"&api_key="+string(keyMatch), nil)
				if err != nil {
					continue
				}

				res, err := client.Do(req)
				if err == nil {
					defer res.Body.Close()
					if res.StatusCode >= 200 && res.StatusCode < 300 {
						s1.Verified = true
					} else {
						if detectors.IsKnownFalsePositive(keyMatch, detectors.DefaultFalsePositives, true) {
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
	return detectorspb.DetectorType_Hive
}
