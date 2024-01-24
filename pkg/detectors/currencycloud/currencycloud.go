package currencycloud

import (
	"context"
	"fmt"
	regexp "github.com/wasilibs/go-re2"
	"io"
	"net/http"
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
	keyPat   = regexp.MustCompile(detectors.PrefixRegex([]string{"currencycloud"}) + `\b([0-9a-z]{64})\b`)
	emailPat = regexp.MustCompile(`\b([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.[a-z]+)\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"currencycloud"}
}

// FromData will find and optionally verify Currencycloud secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	emailMatches := emailPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		for _, emailmatch := range emailMatches {
			if len(emailmatch) != 2 {
				continue
			}
			resEmailMatch := strings.TrimSpace(emailmatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_CurrencyCloud,
				Raw:          []byte(resMatch),
			}
			environments := []string{"devapi", "api"}
			if verify {
				for _, env := range environments {
					// Get authentication token
					payload := strings.NewReader(`{"login_id":"` + resEmailMatch + `","api_key":"` + resMatch + `"`)
					req, err := http.NewRequestWithContext(ctx, "POST", "https://"+env+".currencycloud.com/v2/authenticate/api", payload)
					if err != nil {
						continue
					}
					req.Header.Add("Content-Type", "application/json")
					res, err := client.Do(req)
					if err == nil {
						defer res.Body.Close()
						bodyBytes, err := io.ReadAll(res.Body)
						if err != nil {
							continue
						}
						body := string(bodyBytes)
						if strings.Contains(body, "auth_token") {
							s1.Verified = true
							s1.ExtraData = map[string]string{"environment": fmt.Sprintf("https://%s.currencycloud.com", env)}
							break
						} else {
							if detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, true) {
								continue
							}
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
