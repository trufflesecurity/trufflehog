package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
)

type Scanner struct{ detectors.EndpointSetter }

// Ensure the Scanner satisfies the interfaces at compile time.
var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.Versioner = (*Scanner)(nil)
var _ detectors.EndpointCustomizer = (*Scanner)(nil)

func (Scanner) Version() int            { return 2 }
func (Scanner) DefaultEndpoint() string { return "https://api.github.com" }

var (
	// Oauth token
	// https://developer.github.com/v3/#oauth2-token-sent-in-a-header
	// Token type list:
	// https://github.blog/2021-04-05-behind-githubs-new-authentication-token-formats/
	// https://github.blog/changelog/2022-10-18-introducing-fine-grained-personal-access-tokens/
	keyPat = regexp.MustCompile(`\b((?:ghp|gho|ghu|ghs|ghr|github_pat)_[a-zA-Z0-9_]{36,255})\b`)

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
	UserURL   string `json:"html_url"`
	// Included in GitHub Enterprise Server.
	LdapDN string `json:"ldap_dn"`
}

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"}
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

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Github,
			Raw:          []byte(token),
			ExtraData: map[string]string{
				"rotation_guide": "https://howtorotate.com/docs/tutorials/github/",
			},
		}

		if verify {
			client := common.SaneHttpClient()
			// https://developer.github.com/v3/users/#get-the-authenticated-user
			for _, url := range s.Endpoints(s.DefaultEndpoint()) {
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/user", url), nil)
				if err != nil {
					continue
				}

				req.Header.Set("Content-Type", "application/json; charset=utf-8")
				req.Header.Set("Authorization", fmt.Sprintf("token %s", token))
				res, err := client.Do(req)
				if err == nil {
					if res.StatusCode >= 200 && res.StatusCode < 300 {
						var userResponse userRes
						err = json.NewDecoder(res.Body).Decode(&userResponse)
						res.Body.Close()
						if err == nil {
							s1.Verified = true
							s1.ExtraData["username"] = userResponse.Login
							s1.ExtraData["url"] = userResponse.UserURL
							s1.ExtraData["account_type"] = userResponse.Type
							if userResponse.SiteAdmin {
								s1.ExtraData["site_admin"] = "true"
							}
							if userResponse.Name != "" {
								s1.ExtraData["name"] = userResponse.Name
							}
							if userResponse.Company != "" {
								s1.ExtraData["company"] = userResponse.Company
							}
							if userResponse.LdapDN != "" {
								s1.ExtraData["ldap_dn"] = userResponse.LdapDN
							}

							// GitHub does not seem to consistently return this header.
							scopes := res.Header.Get("X-OAuth-Scopes")
							if scopes != "" {
								s1.ExtraData["scopes"] = scopes
							}
							expiry := res.Header.Get("github-authentication-token-expiration")
							if expiry != "" {
								s1.ExtraData["expires_at"] = expiry
							}
						}
					}
				} else {
					s1.SetVerificationError(err, token)
				}
			}
		}

		if !s1.Verified && detectors.IsKnownFalsePositive(string(s1.Raw), detectors.DefaultFalsePositives, true) {
			continue
		}

		results = append(results, s1)
	}

	return
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Github
}
