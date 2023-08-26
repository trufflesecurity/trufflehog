package skybiometry

import (
	"bytes"
	"context"
	"net/http"
	"net/url"
	"regexp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	keyPat    = regexp.MustCompile(detectors.PrefixRegex([]string{"skybiometry"}) + `\b([0-9a-z]{25,26})\b`)
	secretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"skybiometry"}) + `\b([0-9a-z]{25,26})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("skybiometry")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {

	keyMatches := keyPat.FindAllSubmatch(data, -1)
	secretMatches := secretPat.FindAllSubmatch(data, -1)

	for _, keyMatch := range keyMatches {
		if len(keyMatch) != 2 {
			continue
		}

		key := bytes.TrimSpace(keyMatch[1])

		for _, secretMatch := range secretMatches {
			if len(secretMatch) != 2 {
				continue
			}

			secret := bytes.TrimSpace(secretMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_SkyBiometry,
				Raw:          secret,
			}

			if verify {

				payload := url.Values{}
				payload.Add("api_key", string(key))
				payload.Add("api_secret", string(secret))

				req, err := http.NewRequestWithContext(ctx, "GET", "https://api.skybiometry.com/fc/account/authenticate?"+payload.Encode(), nil)
				if err != nil {
					continue
				}
				res, err := client.Do(req)
				if err == nil {
					defer res.Body.Close()
					if res.StatusCode >= 200 && res.StatusCode < 300 {
						s1.Verified = true
					} else {
						if detectors.IsKnownFalsePositive(key, detectors.DefaultFalsePositives, true) {
							continue
						}
						if detectors.IsKnownFalsePositive(secret, detectors.DefaultFalsePositives, true) {
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
	return detectorspb.DetectorType_SkyBiometry
}
