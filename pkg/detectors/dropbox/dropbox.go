package dropbox

import (
	"context"
	"fmt"
	"net/http"
	"regexp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time
var _ detectors.Detector = (*Scanner)(nil)

var (
	keyPat = regexp.MustCompile(`\b(sl\.[A-Za-z0-9\-\_]{130,140})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"sl."}
}

// FromData will find and optionally verify Dropbox secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {

	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {

		s := detectors.Result{
			DetectorType: detectorspb.DetectorType_Dropbox,
			Raw:          []byte(match[1]),
		}

		if verify {

			baseURL := "https://api.dropboxapi.com/2/users/get_current_account"

			client := common.SaneHttpClient()

			req, _ := http.NewRequestWithContext(ctx, "POST", baseURL, nil)
			req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", match[1]))
			res, err := client.Do(req)
			if err != nil {
				return results, err
			}
			defer res.Body.Close()

			// 200 means good key for get current user
			// 400 is bad (malformed)
			// 403 bad scope
			if res.StatusCode == http.StatusOK {
				s.Verified = true
			}
		}

		if !s.Verified {
			if detectors.IsKnownFalsePositive(string(s.Raw), detectors.DefaultFalsePositives, true) {
				continue
			}
		}

		results = append(results, s)
	}

	return
}
