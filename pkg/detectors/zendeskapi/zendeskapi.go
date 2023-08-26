package zendeskapi

import (
	"bytes"
	"context"
	b64 "encoding/base64"
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

	token  = regexp.MustCompile(detectors.PrefixRegex([]string{"zendesk"}) + `([A-Za-z0-9_-]{40})`)
	email  = regexp.MustCompile(`\b([a-zA-Z-0-9-]{5,16}\@[a-zA-Z-0-9]{4,16}\.[a-zA-Z-0-9]{3,6})\b`)
	domain = regexp.MustCompile(`\b([a-zA-Z-0-9]{3,16}\.zendesk\.com)\b`)
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("zendesk")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {

	tokens := token.FindAllSubmatch(data, -1)
	domains := domain.FindAllSubmatch(data, -1)
	emails := email.FindAllSubmatch(data, -1)

	for _, matchToken := range tokens {
		if len(matchToken) != 2 {
			continue
		}
		resMatch := bytes.TrimSpace(matchToken[1])

		for _, matchDomain := range domains {
			if len(matchDomain) != 2 {
				continue
			}
			resDomain := bytes.TrimSpace(matchDomain[1])

			for _, matchEmail := range emails {
				if len(matchEmail) != 2 {
					continue
				}
				resEmail := bytes.TrimSpace(matchEmail[1])

				if detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, true) {
					continue
				}

				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_ZendeskApi,
					Raw:          resMatch,
				}

				if verify {
					data := fmt.Sprintf("%s/token:%s", string(resEmail), string(resMatch))
					sEnc := b64.StdEncoding.EncodeToString([]byte(data))
					req, err := http.NewRequestWithContext(ctx, "GET", "https://"+string(resDomain)+"/api/v2/users.json", nil)
					if err != nil {
						continue
					}
					req.Header.Add("Authorization", fmt.Sprintf("Basic %s", sEnc))
					res, err := client.Do(req)
					if err == nil {
						defer res.Body.Close()
						if res.StatusCode >= 200 && res.StatusCode < 300 {
							s1.Verified = true
						}
					}
				}

				results = append(results, s1)

			}
		}

	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_ZendeskApi
}
