package github_old

import (
	"context"
	"encoding/json"
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
	// Oauth token
	// https://developer.github.com/v3/#oauth2-token-sent-in-a-header
	keyPat = regexp.MustCompile(`(?i)(?:github|gh|pat)[^\.].{0,40}[ =:'"]+([a-f0-9]{40})\b`)

	// TODO: Oauth2 client_id and client_secret
	// https://developer.github.com/v3/#oauth2-keysecret
)

// TODO: Add secret context?? Information about access, ownership etc
type userRes struct {
	Login     string `json:"login"`
	Type      string `json:"type"`
	SiteAdmin bool   `json:"site_admin"`
	Name      string `json:"name"`
	Company   string `json:"company"`
}

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"github","gh","pat"}
}

// FromData will find and optionally verify GitHub secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		// First match is entire regex, second is the first group.
		if len(match) != 2 {
			continue
		}

		token := match[1]

		specificFPs := []detectors.FalsePositive{"github commit"}
		if detectors.IsKnownFalsePositive(token, specificFPs, false) {
			continue
		}

		s := detectors.Result{
			DetectorType: detectorspb.DetectorType_Github,
			Raw:          []byte(token),
		}

		if verify {
			client := common.SaneHttpClient()
			// https://developer.github.com/v3/users/#get-the-authenticated-user
			req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user", nil)
			if err != nil {
				continue
			}
			req.Header.Add("Content-Type", "application/json; charset=utf-8")
			req.Header.Add("Authorization", fmt.Sprintf("token %s", token))
			res, err := client.Do(req)
			if err == nil {
				if res.StatusCode >= 200 && res.StatusCode < 300 {
					var userResponse userRes
					err = json.NewDecoder(res.Body).Decode(&userResponse)
					res.Body.Close()
					if err == nil {
						s.Verified = true
					}
				}
			}
		}

		if !s.Verified && detectors.IsKnownFalsePositive(token, detectors.DefaultFalsePositives, true) {
			continue
		}

		results = append(results, s)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Github
}
