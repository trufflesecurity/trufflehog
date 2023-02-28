package jiratoken

import (
	"context"
	b64 "encoding/base64"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	tokenPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"jira"}) + `\b([a-zA-Z-0-9]{24})\b`)
	domainPat = regexp.MustCompile(detectors.PrefixRegex([]string{"jira"}) + `\b([a-zA-Z-0-9]{5,24}\.[a-zA-Z-0-9]{3,16}\.[a-zA-Z-0-9]{3,16})\b`)
	emailPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"jira"}) + `\b([a-zA-Z-0-9]{5,24}\@[a-zA-Z-0-9]{3,16}\.com)\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"jira"}
}

// FromData will find and optionally verify JiraToken secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	tokens := tokenPat.FindAllStringSubmatch(dataStr, -1)
	domains := domainPat.FindAllStringSubmatch(dataStr, -1)
	emails := emailPat.FindAllStringSubmatch(dataStr, -1)

	for _, email := range emails {
		if len(email) != 2 {
			continue
		}
		resEmail := strings.TrimSpace(email[1])
		for _, token := range tokens {
			if len(token) != 2 {
				continue
			}
			resToken := strings.TrimSpace(token[1])
			for _, domain := range domains {
				if len(domain) != 2 {
					continue
				}
				resDomain := strings.TrimSpace(domain[1])

				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_JiraToken,
					Raw:          []byte(resToken),
				}

				if verify {

					data := fmt.Sprintf("%s:%s", resEmail, resToken)
					sEnc := b64.StdEncoding.EncodeToString([]byte(data))
					req, err := http.NewRequestWithContext(ctx, "GET", "https://"+resDomain+"/rest/api/3/dashboard", nil)
					if err != nil {
						continue
					}
					req.Header.Add("Accept", "application/json")
					req.Header.Add("Authorization", fmt.Sprintf("Basic %s", sEnc))
					res, err := client.Do(req)
					if err == nil {
						defer res.Body.Close()
						if res.StatusCode >= 200 && res.StatusCode < 300 {
							s1.Verified = true
						}
					}
				}

				if !s1.Verified {
					if detectors.IsKnownFalsePositive(string(s1.Raw), detectors.DefaultFalsePositives, true) {
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
