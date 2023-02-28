package gitlabv2

import (
	"context"
	"fmt"
	"net/http"
	"regexp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	keyPat = regexp.MustCompile(`\b(glpat-[a-zA-Z0-9\-=_]{20,22})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"glpat-"}
}

// FromData will find and optionally verify Gitlab secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}

		secret := detectors.Result{
			DetectorType: detectorspb.DetectorType_Gitlab,
			Raw:          []byte(match[1]),
		}

		if verify {
			// there are 4 read 'scopes' for a gitlab token: api, read_user, read_repo, and read_registry
			// they all grant access to different parts of the API. I couldn't find an endpoint that every
			// one of these scopes has access to, so we just check an example endpoint for each scope. If any
			// of them contain data, we know we have a valid key, but if they all fail, we don't
			baseURL := "https://gitlab.com/api/v4"

			client := common.SaneHttpClient()

			// test `read_user` scope
			req, err := http.NewRequestWithContext(ctx, "GET", baseURL+"/user", nil)
			if err != nil {
				continue
			}
			req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", match[1]))
			res, err := client.Do(req)
			if err == nil {
				res.Body.Close() // The request body is unused.

				// 200 means good key and has `read_user` scope
				// 403 means good key but not the right scope
				// 401 is bad key
				if res.StatusCode == http.StatusOK || res.StatusCode == http.StatusForbidden {
					secret.Verified = true
				}
			}
		}

		if !secret.Verified && detectors.IsKnownFalsePositive(string(secret.Raw), detectors.DefaultFalsePositives, true) {
			continue
		}

		results = append(results, secret)
	}

	return
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Gitlab
}
