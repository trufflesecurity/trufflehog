package gitbook

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"net/http"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	client *http.Client
	// endpoint overrides defaultEndpoint in tests.
	endpoint string
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

const defaultEndpoint = "https://api.gitbook.com"

var (
	defaultClient = common.SaneHttpClient()

	// Personal API tokens are gb_api_ followed by 40 alphanumeric characters.
	apiTokenPat = regexp.MustCompile(`\b(gb_api_[A-Za-z0-9]{40})\b`)

	// OAuth access tokens (atok), OAuth refresh tokens (rtok) and SCIM tokens
	// are their prefix followed by 32 random bytes in unpadded base64url (43
	// characters). base64url includes "-" and "_", so the end of the token is
	// matched explicitly instead of with \b.
	base64URLTokenPat = regexp.MustCompile(`\b((gb_oauth_atok_|gb_oauth_rtok_|gb_scim_)[A-Za-z0-9_-]{43})(?:[^A-Za-z0-9_-]|$)`)
)

const (
	tokenTypeAPI          = "personal_api_token"
	tokenTypeOAuthAccess  = "oauth_access_token"
	tokenTypeOAuthRefresh = "oauth_refresh_token"
	tokenTypeSCIM         = "scim_token"
)

var tokenTypes = map[string]string{
	"gb_oauth_atok_": tokenTypeOAuthAccess,
	"gb_oauth_rtok_": tokenTypeOAuthRefresh,
	"gb_scim_":       tokenTypeSCIM,
}

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"gb_api_", "gb_oauth_", "gb_scim_"}
}

// FromData will find and optionally verify GitBook tokens in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	tokens := make(map[string]string)
	for _, match := range apiTokenPat.FindAllStringSubmatch(dataStr, -1) {
		tokens[match[1]] = tokenTypeAPI
	}
	for _, match := range base64URLTokenPat.FindAllStringSubmatch(dataStr, -1) {
		tokens[match[1]] = tokenTypes[match[2]]
	}

	for token, tokenType := range tokens {
		r := detectors.Result{
			DetectorType: detector_typepb.DetectorType_GitBook,
			Raw:          []byte(token),
			SecretParts:  map[string]string{"key": token},
			ExtraData:    map[string]string{"token_type": tokenType},
		}

		// Only personal API tokens are verified. OAuth access tokens expire
		// after an hour, and the endpoint they can call depends on the scopes
		// they were granted. Refresh tokens can only be checked by redeeming
		// them, which rotates them. SCIM tokens are only accepted by
		// organization-specific endpoints whose URL is not in the token.
		if verify && tokenType == tokenTypeAPI {
			client := cmp.Or(s.client, defaultClient)
			endpoint := cmp.Or(s.endpoint, defaultEndpoint)
			isVerified, vErr := verifyToken(ctx, client, endpoint, token)
			r.Verified = isVerified
			r.SetVerificationError(vErr, token)
		}

		results = append(results, r)
	}

	return results, nil
}

// verifyToken reads the profile of the token's owner.
//
// The error is non-nil only when verification is indeterminate. GitBook
// answers 401 for any unknown, expired or revoked token.
func verifyToken(ctx context.Context, client *http.Client, baseURL, token string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/v1/user", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	switch res.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

// IsFalsePositive keeps the default placeholder checks but skips the English
// word check: GitBook tokens have a fixed prefix and length, and their 40 to
// 43 random characters often contain a short word by chance.
func (s Scanner) IsFalsePositive(result detectors.Result) (bool, string) {
	return detectors.IsKnownFalsePositive(string(result.Raw), detectors.DefaultFalsePositives, false)
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_GitBook
}

func (s Scanner) Description() string {
	return "GitBook is a documentation platform. Personal API tokens and OAuth tokens give access to a user's GitBook content and organizations, and SCIM tokens provision an organization's members."
}
