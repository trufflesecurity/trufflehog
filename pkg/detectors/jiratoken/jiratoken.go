package jiratoken

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

	tokenPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"jira"}) + `\b([a-zA-Z-0-9]{24})\b`)
	domainPat = regexp.MustCompile(detectors.PrefixRegex([]string{"jira"}) + `\b([a-zA-Z-0-9]{5,24}\.[a-zA-Z-0-9]{3,16}\.[a-zA-Z-0-9]{3,16})\b`)
	emailPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"jira"}) + `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`)
)

const (
	failedAuth           = "AUTHENTICATED_FAILED"
	loginReasonHeaderKey = "X-Seraph-LoginReason"
)

func (s Scanner) Keywords() [][]byte {
	return [][]byte{[]byte("jira")}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	tokens := tokenPat.FindAllSubmatch(data, -1)
	domains := domainPat.FindAllSubmatch(data, -1)
	emails := emailPat.FindAllSubmatch(data, -1)

	for _, email := range emails {
		emailSplit := bytes.Split(email[0], []byte(" "))
		if len(emailSplit) != 2 {
			continue
		}

		for _, token := range tokens {
			if len(token) != 2 {
				continue
			}

			for _, domain := range domains {
				if len(domain) != 2 {
					continue
				}

				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_JiraToken,
					Raw:          token[1],
					RawV2:        []byte(fmt.Sprintf("%s:%s:%s", string(emailSplit[1]), string(token[1]), string(domain[1]))),
				}

				if verify {
					dataEncode := b64.StdEncoding.EncodeToString(append(emailSplit[1], token[1]...))
					req, err := http.NewRequestWithContext(ctx, "GET", ("https://" + string(domain[1]) + "/rest/api/3/dashboard"), nil)

					if err != nil {
						continue
					}

					req.Header.Add("Accept", "application/json")
					req.Header.Add("Authorization", fmt.Sprintf("Basic %s", dataEncode))

					res, err := client.Do(req)
					if err == nil {
						defer res.Body.Close()

						if (res.StatusCode >= 200 && res.StatusCode < 300) && res.Header.Get(loginReasonHeaderKey) != failedAuth {
							s1.Verified = true
						}
					}
				}

				if !s1.Verified {
					if detectors.IsKnownFalsePositive(s1.Raw, detectors.DefaultFalsePositives, true) {
						continue
					}
				}

				results = append(results, s1)
			}
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_JiraToken
}
