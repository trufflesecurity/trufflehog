package currencycloud

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
	client   = common.SaneHttpClient()
	keyPat   = regexp.MustCompile(detectors.PrefixRegex([]string{"currencycloud"}) + `\b([0-9a-z]{64})\b`)
	emailPat = regexp.MustCompile(`\b([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.[a-z]+)\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("currencycloud")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllSubmatch(data, -1)
	emailMatches := emailPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])

		for _, emailmatch := range emailMatches {
			if len(emailmatch) != 2 {
				continue
			}
			resEmailMatch := bytes.TrimSpace(emailmatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_CurrencyCloud,
				Raw:          resMatch,
			}

			if verify {
				payload := bytes.NewBuffer([]byte(`{"login_id":"` + string(resEmailMatch) + `","api_key":"` + string(resMatch) + `"`))
				req, err := http.NewRequestWithContext(ctx, "POST", "https://devapi.currencycloud.com/v2/authenticate/api", payload)
				if err != nil {
					continue
				}
				req.Header.Add("Content-Type", "application/json")
				res, err := client.Do(req)
				if err == nil {
					defer res.Body.Close()
					bodyBytes, _ := io.ReadAll(res.Body)
					if bytes.Contains(bodyBytes, []byte("auth_token")) {
						s1.Verified = true
					} else {
						if detectors.IsKnownFalsePositive([]byte(resMatch), detectors.DefaultFalsePositives, true) {
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
	return detectorspb.DetectorType_CurrencyCloud
}
