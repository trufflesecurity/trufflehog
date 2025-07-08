package auth0managementapitoken

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.MaxSecretSizeProvider = (*Scanner)(nil)

var (
	client = detectors.DetectorHttpClientWithLocalAddresses

	// long jwt token but note this is default 8640000 seconds = 24 hours but could be set to maximum 2592000 seconds = 720 hours = 30 days
	// at https://manage.auth0.com/dashboard/us/dev-63memjo3/apis/management/explorer
	managementAPITokenPat = regexp.MustCompile(`\b(ey[a-zA-Z0-9._-]+)\b`)
	domainPat             = regexp.MustCompile(`([a-zA-Z0-9\-]{2,16}\.[a-zA-Z0-9_-]{2,3}\.auth0\.com)`) // could be part of url
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string { return []string{"auth0"} }

const maxSecretSize = 5000

func (Scanner) MaxSecretSize() int64 { return maxSecretSize }

// FromData will find and optionally verify Auth0ManagementApiToken secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	managementAPITokenMatches := managementAPITokenPat.FindAllStringSubmatch(dataStr, -1)
	domainMatches := domainPat.FindAllStringSubmatch(dataStr, -1)

	for _, managementApiTokenMatch := range managementAPITokenMatches {
		managementAPITokenRes := strings.TrimSpace(managementApiTokenMatch[1])
		if len(managementAPITokenRes) < 2000 || len(managementAPITokenRes) > 5000 {
			continue
		}

		for _, domainMatch := range domainMatches {
			domainRes := strings.TrimSpace(domainMatch[1])

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Auth0ManagementApiToken,
				Redacted:     domainRes,
				Raw:          []byte(managementAPITokenRes),
				RawV2:        []byte(managementAPITokenRes + domainRes),
			}

			if verify {
				isVerified, err := verifyMatch(ctx, client, managementAPITokenRes, domainRes)
				s1.Verified = isVerified
				s1.SetVerificationError(err, managementAPITokenRes)
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func verifyMatch(ctx context.Context, client *http.Client, token, domain string) (bool, error) {
	/*
		curl -H "Authorization: Bearer $token" https://domain/api/v2/users
		Reference: https://auth0.com/docs/api/management/v2/users/get-users
	*/
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+domain+"/api/v2/users", http.NoBody)
	if err != nil {
		return false, err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()
	switch res.StatusCode {
	case http.StatusOK, http.StatusForbidden:
		return true, nil
	case http.StatusUnauthorized:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status code %d", res.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Auth0ManagementApiToken
}

func (s Scanner) Description() string {
	return "Auth0 provides authentication and authorization as a service. Auth0 Management API tokens can be used to manage users, roles, permissions, and other aspects of the Auth0 service."
}
