package strava

import (
	"bytes"
	"context"
	"net/http"
	"regexp"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	idPat     = regexp.MustCompile(detectors.PrefixRegex([]string{"strava"}) + `\b([0-9]{5})\b`)
	secretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"strava"}) + `\b([0-9a-z]{40})\b`)
	keyPat    = regexp.MustCompile(detectors.PrefixRegex([]string{"strava"}) + `\b([0-9a-z]{40})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("strava")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	idMatches := idPat.FindAllSubmatch(data, -1)
	secretMatches := secretPat.FindAllSubmatch(data, -1)
	keyMatches := keyPat.FindAllSubmatch(data, -1)

	for _, match := range idMatches {
		if len(match) != 2 {
			continue
		}
		resId := bytes.TrimSpace(match[1])

		for _, secretMatch := range secretMatches {
			if len(secretMatch) != 2 {
				continue
			}
			resSecret := bytes.TrimSpace(secretMatch[1])

			for _, keyMatch := range keyMatches {
				if len(keyMatch) != 2 {
					continue
				}
				resKey := bytes.TrimSpace(keyMatch[1])

				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_Strava,
					Raw:          resId,
					RawV2:        append(resId, resSecret...),
				}

				if verify {
					payload := strings.NewReader("grant_type=refresh_token&client_id=" + string(resId) + "&client_secret=" + string(resSecret) + "&refresh_token=" + string(resKey))

					req, err := http.NewRequestWithContext(ctx, "POST", "https://www.strava.com/oauth/token", payload)
					if err != nil {
						continue
					}
					req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
					res, err := client.Do(req)
					if err == nil {
						defer res.Body.Close()
						if res.StatusCode >= 200 && res.StatusCode < 300 {
							s1.Verified = true
						} else {
							if detectors.IsKnownFalsePositive(resId, detectors.DefaultFalsePositives, true) {
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
	return detectorspb.DetectorType_Strava
}
