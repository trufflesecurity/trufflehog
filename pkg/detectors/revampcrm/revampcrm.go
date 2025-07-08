package revampcrm

import (
	"context"
	regexp "github.com/wasilibs/go-re2"
	"net/http"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"revamp"}) + `\b([a-zA-Z0-9]{40}\b)`)
	idPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"revamp"}) + `\b([a-zA-Z0-9.-@]{25,30})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"revampcrm"}
}

// FromData will find and optionally verify RevampCRM secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	idMatches := idPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		tokenPatMatch := strings.TrimSpace(match[1])

		for _, idMatch := range idMatches {

			userPatMatch := strings.TrimSpace(idMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_RevampCRM,
				Raw:          []byte(tokenPatMatch),
			}
			if verify {
				req, err := http.NewRequestWithContext(ctx, "GET", "https://app.revampcrm.com/api/1.0/User/WhoAmI", nil)
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
	return detectorspb.DetectorType_RevampCRM
}

func (s Scanner) Description() string {
	return "RevampCRM is a customer relationship management service. The credentials can be used to access and manage customer data."
}
