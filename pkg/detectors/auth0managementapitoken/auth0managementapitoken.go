package auth0managementapitoken

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
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

	// long jwt token but note this is default 8640000 seconds = 24 hours but could be set to maximum 2592000 seconds = 720 hours = 30 days
	// at https://manage.auth0.com/dashboard/us/dev-63memjo3/apis/management/explorer
	managementApiTokenPat = regexp.MustCompile(detectors.PrefixRegex([]string{"auth0"}) + `\b(ey[a-zA-Z0-9._-]+)\b`)
	domainPat             = regexp.MustCompile(`([a-zA-Z0-9\-]{2,16}\.[a-zA-Z0-9_-]{2,3}\.auth0\.com)`) // could be part of url
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"auth0"}
}

// FromData will find and optionally verify Auth0ManagementApiToken secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	managementApiTokenMatches := managementApiTokenPat.FindAllStringSubmatch(dataStr, -1)
	domainMatches := domainPat.FindAllStringSubmatch(dataStr, -1)

	for _, managementApiTokenMatch := range managementApiTokenMatches {
		if len(managementApiTokenMatch) != 2 {
			continue
		}
		managementApiTokenRes := strings.TrimSpace(managementApiTokenMatch[1])
		if len(managementApiTokenRes) < 2000 || len(managementApiTokenRes) > 5000 {
			continue
		}

		for _, domainMatch := range domainMatches {
			if len(domainMatch) != 2 {
				continue
			}
			domainRes := strings.TrimSpace(domainMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Auth0ManagementApiToken,
				Redacted:     domainRes,
				Raw:          []byte(managementApiTokenRes),
				RawV2:        []byte(managementApiTokenRes + domainRes),
			}

			if verify {
				/*
				   curl -H "Authorization: Bearer $token" https://domain/api/v2/users
				*/

				req, err := http.NewRequestWithContext(ctx, "GET", "https://"+domainRes+"/api/v2/users", nil)
				if err != nil {
					continue
				}
				req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", managementApiTokenRes))
				res, err := client.Do(req)
				if err == nil {
					defer res.Body.Close()
					if res.StatusCode >= 200 && res.StatusCode < 300 {
						s1.Verified = true
					} else {
						if detectors.IsKnownFalsePositive(managementApiTokenRes, detectors.DefaultFalsePositives, true) {
							continue
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
	return detectorspb.DetectorType_Auth0ManagementApiToken
}
