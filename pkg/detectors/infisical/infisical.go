package infisical

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	client *http.Client
	detectors.EndpointSetter
}

// Ensure the Scanner satisfies the interfaces at compile time.
var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.EndpointCustomizer = (*Scanner)(nil)
var _ detectors.CloudProvider = (*Scanner)(nil)

// CloudEndpoint returns the primary Infisical Cloud region (US).
func (Scanner) CloudEndpoint() string { return "https://app.infisical.com" }

// additionalCloudEndpoints lists the remaining Infisical Cloud regions.
// Cloud regions are isolated: a token issued in one region is unknown on
// the other host, so every region must be tried during verification.
// Self-hosted instances are not listed here. They are verified only when
// an operator configures their URL as a custom verification endpoint.
// https://infisical.com/docs/cli/usage
var additionalCloudEndpoints = []string{
	"https://eu.infisical.com",
}

var (
	defaultClient = common.SaneHttpClient()

	// Infisical service tokens have the form st.<id>.<secret>, where <id> is a
	// UUID and <secret> is 32 lowercase hex characters (crypto.randomBytes(16)).
	// See Infisical/infisical backend/src/services/service-token/service-token-service.ts.
	// The dashboard appends a fourth segment of 32 lowercase hex characters
	// before showing the token (frontend/src/hooks/api/serviceTokens/queries.tsx),
	// and the official CLI rejects tokens without it. Group 1 is the full token
	// as found. Group 2 is the three-part form that authenticates to the API.
	keyPat = regexp.MustCompile(`\b((st\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.[0-9a-f]{32})(?:\.[0-9a-f]{32})?)\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"st."}
}

// FromData will find and optionally verify Infisical service tokens in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	// Map each full token to the three-part form sent for verification.
	uniqueMatches := make(map[string]string)
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = match[2]
	}

	for resMatch, authToken := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_Infisical,
			Raw:          []byte(resMatch),
			SecretParts:  map[string]string{"key": resMatch},
		}

		if verify {
			client := s.VerificationClient(cmp.Or(s.client, defaultClient))

			// Verification targets the Infisical Cloud regions (US and EU)
			// plus any operator-configured endpoints, such as self-hosted
			// instances. URLs in the scanned data are never used.
			//
			// Only non-nil errors overwrite lastErr so that a clean 404 from
			// the wrong region doesn't erase a transient failure (429, 5xx,
			// timeout) from a region that might be authoritative.
			var lastErr error
			for _, baseURL := range s.Endpoints(additionalCloudEndpoints...) {
				isVerified, vErr := verifyServiceToken(ctx, client, baseURL, authToken)
				s1.Verified = isVerified
				if vErr != nil {
					lastErr = vErr
				}
				if isVerified {
					lastErr = nil
					s1.ExtraData = map[string]string{"endpoint": baseURL}
					break
				}
			}
			s1.SetVerificationError(lastErr, resMatch)
		}

		results = append(results, s1)
	}

	return results, nil
}

// verifyServiceToken checks a three-part service token against one Infisical
// instance. It calls GET /api/v2/service-token, which returns only the
// token's metadata. The official CLI calls the same route to read token
// details. Do not switch to /api/v3/secrets/raw: for a token with one exact
// scope, that route returns the plaintext secret values and writes a secret
// read to the owner's audit log.
//
// The first return value reports whether the token verified. The error is
// non-nil only when verification is indeterminate (the token's validity
// could not be established from this response); the caller records it via
// Result.SetVerificationError so an ambiguous result is not silently
// dropped as a determinate miss.
func verifyServiceToken(ctx context.Context, client *http.Client, baseURL, token string) (bool, error) {
	endpoint, err := url.JoinPath(baseURL, "/api/v2/service-token")
	if err != nil {
		return false, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	switch {
	case res.StatusCode == http.StatusOK:
		return true, nil
	case res.StatusCode == http.StatusUnauthorized, res.StatusCode == http.StatusNotFound:
		// Determinately invalid: the instance does not recognize this token.
		return false, nil
	case res.StatusCode == http.StatusForbidden:
		// Ambiguous: Infisical returns 403 for an expired token, and a proxy
		// or WAF in front of the instance can reject requests for non-auth
		// reasons. Do not read this as "not a secret".
		return false, fmt.Errorf("forbidden response (HTTP 403): token validity could not be determined")
	case res.StatusCode == http.StatusTooManyRequests:
		// Transient rate limit; retrying later may verify the token.
		return false, fmt.Errorf("rate limited (HTTP 429): token validity could not be determined")
	case res.StatusCode >= 500:
		// Transient server failure; the token's validity is unknown.
		return false, fmt.Errorf("server error (HTTP %d): token validity could not be determined", res.StatusCode)
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_Infisical
}

func (s Scanner) Description() string {
	return "Infisical is an open-source secrets management platform. Service tokens can be used to read and write secrets within their scoped environments and paths."
}
