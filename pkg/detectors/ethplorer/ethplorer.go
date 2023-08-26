package ethplorer

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

	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"ethplorer"}) + `\b([a-z0-9A-Z-]{22})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("ethplorer")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Ethplorer,
			Raw:          resMatch,
		}

		if verify {
			payload := bytes.NewReader([]byte("apiKey=" + string(resMatch) + "&addresses=0xb2930b35844a230f00e51431acae96fe543a0347%2C0xb52d3141ee731fac89927476c6a5207b37cd72ff"))
			req, err := http.NewRequestWithContext(ctx, "POST", "https://api-mon.ethplorer.io/createPool", payload)
			if err != nil {
				continue
			}
			req.Header.Add("accept", "application/json")
			req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
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

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Ethplorer
}
