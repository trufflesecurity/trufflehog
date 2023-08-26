package cryptocompare

import (
	"bytes"
	"context"
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

	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"cryptocompare"}) + `\b([a-z-0-9]{64})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("cryptocompare")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_CryptoCompare,
			Raw:          resMatch,
		}

		if verify {
			req, err := http.NewRequestWithContext(ctx, "GET", "https://min-api.cryptocompare.com/data/blockchain/list?api_key="+string(resMatch), nil)
			if err != nil {
				continue
			}
			res, err := client.Do(req)
			if err == nil {
				bodyBytes, err := io.ReadAll(res.Body)
				if err != nil {
					continue
				}
				errCode := bytes.Contains(bodyBytes, []byte(`"Response":"Success"`))
				defer res.Body.Close()
				if res.StatusCode >= 200 && res.StatusCode < 300 {
					if errCode {
						s1.Verified = true
					} else {
						s1.Verified = false
					}
				} else {
					if detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, true) {
						continue
					}
				}
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_CryptoCompare
}
