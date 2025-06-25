package circleci

import (
	"context"
	"net/http"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"circle"}) + `([a-fA-F0-9]{40})`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"circle"}
}

// FromData will find and optionally verify Circle secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {

		token := match[1]

		result := detectors.Result{
			DetectorType: detectorspb.DetectorType_Circle,
			Raw:          []byte(token),
		}

		if verify {
			client := common.SaneHttpClient()
			// https://circleci.com/docs/api/#authentication
			req, err := http.NewRequestWithContext(ctx, "GET", "https://circleci.com/api/v2/me", nil)
			if err != nil {
				continue
			}
			req.Header.Add("Accept", "application/json;")
			req.Header.Add("Circle-Token", token)
			res, err := client.Do(req)
			if err == nil {
				defer res.Body.Close()
			}
			if res != nil && res.StatusCode >= 200 && res.StatusCode < 300 {
				result.Verified = true
			}
		}

		results = append(results, result)
	}

	return
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Circle
}

func (s Scanner) Description() string {
	return "CircleCI is a continuous integration and delivery platform used to build, test, and deploy software. CircleCI tokens can be used to interact with the CircleCI API and access various resources and functionalities."
}
