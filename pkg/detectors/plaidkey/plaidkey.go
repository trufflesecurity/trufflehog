package plaidkey

import (
	"context"
	"fmt"
	regexp "github.com/wasilibs/go-re2"
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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"plaid"}) + `\b([a-z0-9]{30})\b`)
	idPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"plaid"}) + `\b([a-z0-9]{24})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"plaid"}
}

// FromData will find and optionally verify PlaidKey secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	idMatches := idPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		for _, idMatch := range idMatches {
			if len(idMatch) != 2 {
				continue
			}
			idresMatch := strings.TrimSpace(idMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_PlaidKey,
				Raw:          []byte(resMatch),
			}
			environments := []string{"development", "production"}
			if verify {
				for _, env := range environments {
					payload := strings.NewReader(`{"client_id":"` + idresMatch + `","secret":"` + resMatch + `","user":{"client_user_id":"60e3ee4019a2660010f8bc54","phone_number_verified_time":"0001-01-01T00:00:00Z","email_address_verified_time":"0001-01-01T00:00:00Z"},"client_name":"Plaid Test App","products":["auth","transactions"],"country_codes":["US"],"webhook":"https://webhook-uri.com","account_filters":{"depository":{"account_subtypes":["checking","savings"]}},"language":"en","link_customization_name":"default"}`)
					req, err := http.NewRequestWithContext(ctx, "POST", "https://"+env+".plaid.com/link/token/create", payload)
					if err != nil {
						continue
					}
					req.Header.Add("Content-Type", "application/json")
					res, err := client.Do(req)
					if err == nil {
						defer res.Body.Close()
						if res.StatusCode >= 200 && res.StatusCode < 300 {
							s1.Verified = true
							s1.ExtraData = map[string]string{"environment": fmt.Sprintf("https://%s.plaid.com", env)}
						} else {
							// This function will check false positives for common test words, but also it will make sure the key appears 'random' enough to be a real key.
							if detectors.IsKnownFalsePositive(resMatch, detectors.DefaultFalsePositives, true) {
								continue
							}
						}
					}
				}
				results = append(results, s1)
				// if the environment is dev, we don't need to check production
				if s1.Verified {
					break
				}
			}
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_PlaidKey
}
