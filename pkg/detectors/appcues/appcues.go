package appcues

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

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
	keyPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"appcues"}) + `\b([a-z0-9-]{36})\b`)
	userPat = regexp.MustCompile(detectors.PrefixRegex([]string{"appcues"}) + `\b([a-z0-9-]{39})\b`)
	idPat   = regexp.MustCompile(detectors.PrefixRegex([]string{"appcues"}) + `\b([0-9]{5})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"appcues"}
}

// FromData will find and optionally verify Appcues secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	userMatches := userPat.FindAllStringSubmatch(dataStr, -1)
	idMatches := idPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		for _, userMatch := range userMatches {

			resUserMatch := strings.TrimSpace(userMatch[1])

			for _, idMatch := range idMatches {

				resIdMatch := strings.TrimSpace(idMatch[1])

				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_Appcues,
					Raw:          []byte(resMatch),
					RawV2:        []byte(resMatch + resUserMatch),
				}
				if verify {
					req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://api.appcues.com/v2/accounts/%s/flows", resIdMatch), nil)
					if err != nil {
						continue
					}
					req.SetBasicAuth(resUserMatch, resMatch)
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
	return detectorspb.DetectorType_Appcues
}

func (s Scanner) Description() string {
	return "Appcues is a user engagement platform that helps create personalized user experiences. The detected credentials can be used to access and manage user engagement flows and data."
}
