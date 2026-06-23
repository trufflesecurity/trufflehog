package blackduck

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	client *http.Client
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = detectors.DetectorHttpClientWithLocalAddresses

	// Black Duck API tokens are base64("<uuid>:<uuid>"), i.e. 100 base64 chars
	// ending in "==". isValidTokenFormat confirms the decoded uuid pair below.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"blackduck", "black_duck"}) + `\b([A-Za-z0-9+/]{96,140}={0,2})`)
	// Black Duck is self-hosted, so we need the server URL to verify.
	endpointPat = regexp.MustCompile(detectors.PrefixRegex([]string{"blackduck", "black_duck"}) + `\b(https?://[a-zA-Z0-9.-]+(?::[0-9]{2,5})?)`)

	uuidPat = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"blackduck", "black_duck"}
}

// isValidTokenFormat checks the candidate base64-decodes to a "uuid:uuid" pair.
func isValidTokenFormat(candidate string) bool {
	decoded, err := base64.StdEncoding.DecodeString(candidate)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(candidate, "="))
		if err != nil {
			return false
		}
	}

	parts := strings.Split(string(decoded), ":")
	if len(parts) != 2 {
		return false
	}
	return uuidPat.MatchString(parts[0]) && uuidPat.MatchString(parts[1])
}

// FromData will find and optionally verify Black Duck secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	endpointMatches := endpointPat.FindAllStringSubmatch(dataStr, -1)

	uniqueTokens := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		token := strings.TrimSpace(match[1])
		if isValidTokenFormat(token) {
			uniqueTokens[token] = struct{}{}
		}
	}

	for token := range uniqueTokens {
		for _, endpointMatch := range endpointMatches {
			resEndpointMatch := strings.TrimSpace(endpointMatch[1])

			u, err := detectors.ParseURLAndStripPathAndParams(resEndpointMatch)
			if err != nil {
				// skip invalid URLs
				continue
			}
			u.Path = "/api/tokens/authenticate"

			s1 := detectors.Result{
				DetectorType: detector_typepb.DetectorType_BlackDuck,
				Raw:          []byte(token),
				RawV2:        []byte(token + resEndpointMatch),
				SecretParts: map[string]string{
					"key": token,
					"url": resEndpointMatch,
				},
			}

			if verify {
				client := s.client
				if client == nil {
					client = defaultClient
				}
				isVerified, verErr := verifyToken(ctx, client, u.String(), token)
				s1.Verified = isVerified
				if verErr != nil {
					s1.SetVerificationError(verErr, token)
				}
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

// verifyToken calls the Black Duck token-auth endpoint. 200 means valid,
// 401/403 mean invalid, anything else is treated as an indeterminate error.
func verifyToken(ctx context.Context, client *http.Client, url, token string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Accept", "application/vnd.blackducksoftware.user-4+json")

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
	case http.StatusUnauthorized, http.StatusForbidden:
		// invalid token, nothing to do
		return false, nil
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_BlackDuck
}

func (s Scanner) Description() string {
	return "Black Duck is a software composition analysis (SCA) tool used to identify security and license risks in open-source dependencies. Black Duck API tokens authenticate to the Black Duck server's REST API and can expose scan results and project data."
}
