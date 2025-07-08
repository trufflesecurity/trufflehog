package onepagecrm

import (
	"context"
	regexp "github.com/wasilibs/go-re2"
	"net/http"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"onepagecrm"}) + `\b([a-zA-Z0-9=]{44})`)
	idPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"onepagecrm"}) + `\b([a-z0-9]{24})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"onepagecrm"}
}

// FromData will find and optionally verify OnepageCRM secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	idMatches := idPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		tokenPatMatch := strings.TrimSpace(match[1])

		for _, idMatch := range idMatches {

			userPatMatch := strings.TrimSpace(idMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_OnepageCRM,
				Raw:          []byte(tokenPatMatch),
			}
			if verify {
				req, err := http.NewRequestWithContext(ctx, "GET", "https://app.onepagecrm.com/api/v3/contacts.json?per_page=20&page=1", nil)
				if err != nil {
					continue
				}
				req.SetBasicAuth(userPatMatch, tokenPatMatch)
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

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_OnepageCRM
}

func (s Scanner) Description() string {
	return "OnepageCRM is a simple CRM system designed for small businesses. The API keys can be used to access and manage contacts, deals, and other CRM data."
}
