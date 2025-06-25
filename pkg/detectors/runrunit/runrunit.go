package runrunit

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
	keyPat       = regexp.MustCompile(detectors.PrefixRegex([]string{"runrunit"}) + `\b([0-9a-f]{32})\b`)
	userTokenPat = regexp.MustCompile(detectors.PrefixRegex([]string{"runrunit"}) + `\b([0-9A-Za-z]{18,20})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"runrunit"}
}

// FromData will find and optionally verify RunRunIt secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	userTokenMatches := userTokenPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		resMatch := strings.TrimSpace(match[1])

		for _, userTokenMatch := range userTokenMatches {
			resUserTokenMatch := strings.TrimSpace(userTokenMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_RunRunIt,
				Raw:          []byte(resMatch),
			}

			if verify {
				req, err := http.NewRequestWithContext(ctx, "GET", "https://runrun.it/api/v1.0/users", nil)
				if err != nil {
					continue
				}
				req.Header.Add("App-Key", resMatch)
				req.Header.Add("User-Token", resUserTokenMatch)
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
	return detectorspb.DetectorType_RunRunIt
}

func (s Scanner) Description() string {
	return "RunRunIt is a project management tool. App-Key and User-Token can be used to access and modify project data."
}
