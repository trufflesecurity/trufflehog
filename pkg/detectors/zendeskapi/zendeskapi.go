package zendeskapi

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

	token  = regexp.MustCompile(detectors.PrefixRegex([]string{"zendesk"}) + `([A-Za-z0-9_-]{40})`)
	email  = regexp.MustCompile(`\b([a-zA-Z-0-9-]{5,16}\@[a-zA-Z-0-9]{4,16}\.[a-zA-Z-0-9]{3,6})\b`)
	domain = regexp.MustCompile(`\b([a-zA-Z-0-9]{3,16}\.zendesk\.com)\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"zendesk"}
}

// FromData will find and optionally verify ZendeskApi secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	tokens := token.FindAllStringSubmatch(dataStr, -1)
	domains := domain.FindAllStringSubmatch(dataStr, -1)
	emails := email.FindAllStringSubmatch(dataStr, -1)

	for _, token := range tokens {
		if len(token) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(token[1])

		var resDomain string
		for _, domain := range domains {
			if len(domain) != 2 {
				continue
			}
			resDomain = strings.TrimSpace(domain[1])

			for _, email := range emails {
				if len(email) != 2 {
					continue
				}
				resEmail := strings.TrimSpace(email[1])

				if detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, true) {
					continue
				}

				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_ZendeskApi,
					Raw:          []byte(resMatch),
				}

				if verify {
					data := fmt.Sprintf("%s/token:%s", resEmail, resMatch)
					sEnc := b64.StdEncoding.EncodeToString([]byte(data))
					req, err := http.NewRequestWithContext(ctx, "GET", "https://"+resDomain+"/api/v2/users.json", nil)
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
