package companyhub

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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"companyhub"}) + `\b([0-9a-zA-Z]{20})\b`)
	idPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"companyhub"}) + `\b([a-zA-Z0-9$%^=-]{4,32})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("companyhub")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	keyMatches := keyPat.FindAllSubmatch(data, -1)
	idMatches := idPat.FindAllSubmatch(data, -1)

	for _, keyMatch := range keyMatches {
		if len(keyMatch) != 2 {
			continue
		}

		resKeyMatch := bytes.TrimSpace(keyMatch[1])

		for _, idMatch := range idMatches {
			if len(idMatch) != 2 {
				continue
			}

			resIdMatch := bytes.TrimSpace(idMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_CompanyHub,
				Raw:          resKeyMatch,
				RawV2:        append(resKeyMatch, resIdMatch...),
			}

			if verify {
				req, err := http.NewRequestWithContext(ctx, "GET", "https://api.companyhub.com/v1/me", nil)
				if err != nil {
					continue
				}
				req.Header.Add("Authorization", string(bytes.Join([][]byte{resIdMatch, resKeyMatch}, []byte(" "))))
				req.Header.Add("Content-Type", "application/json")

				res, err := client.Do(req)
				if err == nil {
					defer res.Body.Close()
					if res.StatusCode >= 200 && res.StatusCode < 300 {
						s1.Verified = true
					} else {
						if detectors.IsKnownFalsePositive(resKeyMatch, detectors.DefaultFalsePositives, true) {
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
	return detectorspb.DetectorType_CompanyHub
}
