package rownd

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
	client    = common.SaneHttpClient()
	keyPat    = regexp.MustCompile(detectors.PrefixRegex([]string{"rownd"}) + `\b([a-z0-9]{8}\-[a-z0-9]{4}\-[a-z0-9]{4}\-[a-z0-9]{4}\-[a-z0-9]{12})\b`)
	secretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"rownd"}) + `\b([a-z0-9]{48})\b`)
	idPat     = regexp.MustCompile(detectors.PrefixRegex([]string{"rownd"}) + `\b([0-9]{18})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("rownd")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	idMatches := idPat.FindAllSubmatch(data, -1)
	keyMatches := keyPat.FindAllSubmatch(data, -1)
	secretMatches := secretPat.FindAllSubmatch(data, -1)

	for _, idMatch := range idMatches {
		if len(idMatch) != 2 {
			continue
		}
		resId := bytes.TrimSpace(idMatch[1])

		for _, match := range keyMatches {
			if len(match) != 2 {
				continue
			}
			keyMatch := bytes.TrimSpace(match[1])

			for _, secret := range secretMatches {
				if len(secret) != 2 {
					continue
				}
				secretMatch := bytes.TrimSpace(secret[1])

				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_Rownd,
					Raw:          keyMatch,
					RawV2:        append(keyMatch, secretMatch...),
				}

				if verify {
					req, err := http.NewRequestWithContext(ctx, "GET", "https://api.rownd.io/applications/"+string(resId)+"/users/data", nil)
					if err != nil {
						continue
					}
					req.Header.Add("x-rownd-app-key", string(keyMatch))
					req.Header.Add("x-rownd-app-secret", string(secretMatch))
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
	}
	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Rownd
}
