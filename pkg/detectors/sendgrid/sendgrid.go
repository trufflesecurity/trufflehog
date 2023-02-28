package sendgrid

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"sendgrid"}) + `(SG\.[\w\-_]{20,24}\.[\w\-_]{39,50})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"SG."}
}

// FromData will find and optionally verify Sendgrid secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		res := strings.TrimSpace(match[1])

		s := detectors.Result{
			DetectorType: detectorspb.DetectorType_SendGrid,
			Raw:          []byte(res),
		}

		if verify {
			// there are a few endpoints we can check, but templates seems the least sensitive.
			// 403 will be issued if the scope is wrong but the key is correct
			baseURL := "https://api.sendgrid.com/v3/templates"

			// test `read_user` scope
			req, err := http.NewRequestWithContext(ctx, "GET", baseURL, nil)
			if err != nil {
				continue
			}
			req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", res))
			req.Header.Add("Content-Type", "application/json")
			res, err := client.Do(req)
			if err == nil {
				res.Body.Close() // The request body is unused.

				// 200 means good key and has `templates` scope
				// 403 means good key but not the right scope
				// 401 is bad key
				if res.StatusCode == http.StatusOK || res.StatusCode == http.StatusForbidden {
					s.Verified = true
				}
			}
		}

		if !s.Verified && detectors.IsKnownFalsePositive(string(s.Raw), detectors.DefaultFalsePositives, true) {
			continue
		}

		results = append(results, s)
	}

	return
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_SendGrid
}
