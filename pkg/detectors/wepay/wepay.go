package wepay

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

	appIDPat = regexp.MustCompile(`\b(\d{6})\b`)
	keyPat   = regexp.MustCompile(detectors.PrefixRegex([]string{"wepay"}) + `\b([a-zA-Z0-9_?]{62})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("wepay")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllSubmatch(data, -1)
	appIDmatches := appIDPat.FindAllSubmatch(data, -1)

	resAppIDMatch := []byte("")
	for _, appIDMatch := range appIDmatches {
		if len(appIDMatch) != 2 {
			continue
		}
		resAppIDMatch = bytes.TrimSpace(appIDMatch[1])
	}

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_WePay,
			Raw:          resMatch,
		}

		if verify {
			req, err := http.NewRequestWithContext(ctx, "GET", "https://stage-api.wepay.com/payments?type=credit_card&credit_card=4003830171874018", nil)
			if err != nil {
				continue
			}
			req.Header.Add("App-Token", string(resMatch))
			req.Header.Add("App-Id", string(resAppIDMatch))
			req.Header.Add("Api-Version", "3.0")
			req.Header.Add("Accept", "application/json")
			req.Header.Add("Unique-Key", "Unique-Key0")

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
	return detectorspb.DetectorType_WePay
}
