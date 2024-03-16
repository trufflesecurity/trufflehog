package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{ detectors.EndpointSetter }

// Ensure the Scanner satisfies the interfaces at compile time.
var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.Versioner = (*Scanner)(nil)
var _ detectors.EndpointCustomizer = (*Scanner)(nil)

func (Scanner) Version() int            { return 1 }
func (Scanner) DefaultEndpoint() string { return "https://api.github.com" }

var (
	// Oauth token
	// https://developer.github.com/v3/#oauth2-token-sent-in-a-header
	keyPat = regexp.MustCompile(`(?i)(?:github|gh|pat|token)[^\.].{0,40}[ =:'"]+([a-f0-9]{40})\b`)

	// TODO: Oauth2 client_id and client_secret
	// https://developer.github.com/v3/#oauth2-keysecret
)

// TODO: Add secret context?? Information about access, ownership etc
type UserRes struct {
	Login     string `json:"login"`
	Type      string `json:"type"`
	SiteAdmin bool   `json:"site_admin"`
	Name      string `json:"name"`
	Company   string `json:"company"`
	UserURL   string `json:"html_url"`
	// Included in GitHub Enterprise Server.
	LdapDN string `json:"ldap_dn"`
}

type HeaderInfo struct {
	Scopes string `json:"X-OAuth-Scopes"`
	Expiry string `json:"github-authentication-token-expiration"`
}

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"github", "gh", "pat", "token"}
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

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Github,
			Raw:          []byte(token),
			ExtraData: map[string]string{
				"rotation_guide": "https://howtorotate.com/docs/tutorials/github/",
				"version":        fmt.Sprintf("%d", s.Version()),
			},
		}

		if verify {
			client := common.SaneHttpClient()

			isVerified, userResponse, headers, err := s.VerifyGithub(ctx, client, token)
			s1.Verified = isVerified
			s1.SetVerificationError(err, token)

			if userResponse != nil {
				SetUserResponse(userResponse, &s1)
			}
			if headers != nil {
				SetHeaderInfo(headers, &s1)
			}
		}

		if !s1.Verified && detectors.IsKnownFalsePositive(token, detectors.DefaultFalsePositives, true) {
			continue
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) VerifyGithub(ctx context.Context, client *http.Client, token string) (bool, *UserRes, *HeaderInfo, error) {
	// https://developer.github.com/v3/users/#get-the-authenticated-user
	var requestErr error
	for _, url := range s.Endpoints(s.DefaultEndpoint()) {
		requestErr = nil

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/user", url), nil)
		if err != nil {
			continue
		}

		req.Header.Set("Content-Type", "application/json; charset=utf-8")
		req.Header.Set("Authorization", fmt.Sprintf("token %s", token))
		res, err := client.Do(req)
		if err != nil {
			requestErr = err
			continue
		}

		if res.StatusCode >= 200 && res.StatusCode < 300 {
			var userResponse UserRes
			err = json.NewDecoder(res.Body).Decode(&userResponse)
			res.Body.Close()
			if err == nil {
				// GitHub does not seem to consistently return this header.
				scopes := res.Header.Get("X-OAuth-Scopes")
				expiry := res.Header.Get("github-authentication-token-expiration")
				return true, &userResponse, &HeaderInfo{Scopes: scopes, Expiry: expiry}, nil
			}
		}
	}
	return false, nil, nil, requestErr
}

func SetUserResponse(userResponse *UserRes, s1 *detectors.Result) {
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
}

func SetHeaderInfo(headers *HeaderInfo, s1 *detectors.Result) {
	if headers.Scopes != "" {
		s1.ExtraData["scopes"] = headers.Scopes
	}
	if headers.Expiry != "" {
		s1.ExtraData["expiry"] = headers.Expiry
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Github
}
