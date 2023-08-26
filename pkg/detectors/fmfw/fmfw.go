package fmfw

import (
	"bytes"
	"context"
	"net/http"
	"regexp"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"fmfw"}) + `\b([a-zA-Z0-9_-]{32})\b`)
	idPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"fmfw"}) + `\b([a-zA-Z0-9-]{32})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("fmfw")}
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
				DetectorType: detectorspb.DetectorType_Fmfw,
				Raw:          tokenPatMatch,
			}

			if verify {
				timeout := 10 * time.Second
				client.Timeout = timeout
				req, err := http.NewRequestWithContext(ctx, "GET", "https://api.fmfw.io/api/3/spot/balance", nil)
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
	return detectorspb.DetectorType_Fmfw
}
