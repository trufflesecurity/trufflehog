package apiflash

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

	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"apiflash"}) + `\b([a-z0-9]{32})\b`)
	urlPat = regexp.MustCompile(detectors.PrefixRegex([]string{"apiflash"}) + `\b([a-zA-Z0-9\S]{21,30})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("apiflash")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllSubmatch(data, -1)
	urlMatches := urlPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])

		for _, urlMatch := range urlMatches {
			if len(urlMatch) != 2 {
				continue
			}

			resUrlMatch := bytes.TrimSpace(urlMatch[1])
			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Apiflash,
				Raw:          resMatch,
				RawV2:        append(resMatch, resUrlMatch...),
			}

			if verify {
				req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://api.apiflash.com/v1/urltoimage?url=%s&access_key=%s", string(resUrlMatch), string(resMatch)), nil)
				if err != nil {
					continue
				}
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
	return detectorspb.DetectorType_Apiflash
}
