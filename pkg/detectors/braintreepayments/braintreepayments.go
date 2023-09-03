package braintreepayments

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

	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"braintree"}) + `\b([0-9a-f]{32})\b`)
	idPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"braintree"}) + `\b([0-9a-z]{16})\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("braintree")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	matches := keyPat.FindAllSubmatch(data, -1)
	idMatches := idPat.FindAllSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(match[1])

		for _, idMatch := range idMatches {
			if len(idMatch) != 2 {
				continue
			}

			resIdMatch := bytes.TrimSpace(idMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_BraintreePayments,
				Raw:          resMatch,
			}

			if verify {
				payload := bytes.NewBufferString(`{"query": "query { ping }"}`)
				req, err := http.NewRequestWithContext(ctx, "POST", "https://payments.braintree-api.com/graphql", payload)
				if err != nil {
					continue
				}
				req.Header.Add("Content-Type", "application/json")
				req.Header.Add("Braintree-Version", "2019-01-01")
				req.SetBasicAuth(string(resIdMatch), string(resMatch))
				res, err := client.Do(req)
				if err == nil {
					bodyBytes, err := io.ReadAll(res.Body)
					if err != nil {
						continue
					}

					validResponse := bytes.Contains(bodyBytes, []byte(`"data":{`))

					defer res.Body.Close()
					if res.StatusCode >= 200 && res.StatusCode < 300 && validResponse {
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
	return detectorspb.DetectorType_BraintreePayments
}
