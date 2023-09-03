package digitaloceanv2

import (
	"bytes"
	"context"
	"fmt"
	"io"
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
	keyPat = regexp.MustCompile(`\b((?:dop|doo|dor)_v1_[a-f0-9]{64})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("dop_v1_"), []byte("doo_v1_"), []byte("dor_v1_")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_DigitalOceanV2,
			Raw:          resMatch,
		}

		if verify {
			switch {
			case bytes.HasPrefix(resMatch, []byte("dor_v1_")):
				req, err := http.NewRequestWithContext(ctx, "GET", "https://cloud.digitalocean.com/v1/oauth/token?grant_type=refresh_token&refresh_token="+string(resMatch), nil)
				if err != nil {
					continue
				}

				res, err := client.Do(req)
				if err == nil {
					bodyBytes, err := io.ReadAll(res.Body)

					if err != nil {
						continue
					}

					validResponse := bytes.Contains(bodyBytes, []byte(`"access_token"`))
					defer res.Body.Close()

					if res.StatusCode >= 200 && res.StatusCode < 300 && validResponse {
						s1.Verified = true
					} else {
						if detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, true) {
							continue
						}
					}
				}

			case bytes.HasPrefix(resMatch, []byte("doo_v1_")), bytes.HasPrefix(resMatch, []byte("dop_v1_")):
				req, err := http.NewRequestWithContext(ctx, "GET", "https://api.digitalocean.com/v2/account", nil)
				if err != nil {
					continue
				}
				req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", string(resMatch)))
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
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_DigitalOceanV2
}
