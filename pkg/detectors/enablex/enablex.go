package enablex

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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"enablex"}) + `\b([a-zA-Z0-9]{36})\b`)
	idPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"enablex"}) + `\b([a-z0-9]{24})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("enablex")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllSubmatch(data, -1)
	idMatches := idPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		tokenPatMatch := bytes.TrimSpace(match[1])

		for _, idMatch := range idMatches {
			if len(idMatch) != 2 {
				continue
			}
			userPatMatch := bytes.TrimSpace(idMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Enablex,
				Raw:          tokenPatMatch,
			}

			if verify {
				req, err := http.NewRequest("GET", "https://api.enablex.io/voice/v1/call", nil)
				if err != nil {
					continue
				}
				req.SetBasicAuth(string(userPatMatch), string(tokenPatMatch))
				res, err := client.Do(req)
				if err == nil {
					defer res.Body.Close()
					if res.StatusCode >= 200 && res.StatusCode < 300 {
						s1.Verified = true
					} else {
						if detectors.IsKnownFalsePositive(tokenPatMatch, detectors.DefaultFalsePositives, true) {
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
	return detectorspb.DetectorType_Enablex
}
