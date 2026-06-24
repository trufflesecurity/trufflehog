package visiblenpmregistryauthdata

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	client *http.Client
	// registryBaseURL exists for deterministic tests.
	registryBaseURL string
	detectors.DefaultMultiPartCredentialProvider
}

var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.CustomFalsePositiveChecker = (*Scanner)(nil)

const defaultNpmRegistryBaseURL = "https://registry.npmjs.org"

var (
	defaultClient = common.SaneHttpClient()

	// Match visible auth data in .npmrc-like contexts.
	// Example: //registry.npmjs.org/:_authToken=npm_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
	authTokenLinePat = regexp.MustCompile(`(?im)(?:^|[\n\r])\s*(?:@[^:\s]+:)?(?:\/\/[^\s]+\/:)?_authToken\s*=\s*([^\s"'` + "`" + `]+)`)

	// Example: //registry.npmjs.org/:_auth=base64value
	authLinePat = regexp.MustCompile(`(?im)(?:^|[\n\r])\s*(?:@[^:\s]+:)?(?:\/\/[^\s]+\/:)?_auth\s*=\s*([A-Za-z0-9+/=_-]{16,})`)

	// NPM token shapes we can actively verify via whoami endpoint.
	verifyableTokenPat = regexp.MustCompile(`^(?:npm_[A-Za-z0-9]{36}|[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})$`)
)

func (s Scanner) Keywords() []string {
	return []string{"_authToken", "_auth", "registry.npmjs.org", "npmrc"}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_VisibleNpmRegistryAuthData
}

func (s Scanner) Description() string {
	return "Visible npm registry auth data in npmrc files can expose publish/install privileges to private or public registries."
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueTokenMatches := make(map[string]struct{})
	for _, match := range authTokenLinePat.FindAllStringSubmatch(dataStr, -1) {
		if len(match) < 2 {
			continue
		}
		uniqueTokenMatches[strings.TrimSpace(match[1])] = struct{}{}
	}

	uniqueAuthMatches := make(map[string]struct{})
	for _, match := range authLinePat.FindAllStringSubmatch(dataStr, -1) {
		if len(match) < 2 {
			continue
		}
		uniqueAuthMatches[strings.TrimSpace(match[1])] = struct{}{}
	}

	client := s.getClient()
	for value := range uniqueTokenMatches {
		r := detectors.Result{
			DetectorType: s.Type(),
			Raw:          []byte(value),
			SecretParts: map[string]string{
				"auth_kind": "authToken",
				"key":       value,
			},
			ExtraData: map[string]string{
				"rotation_guide": "https://howtorotate.com/docs/tutorials/npm/",
			},
		}

		if verify && verifyableTokenPat.MatchString(value) {
			isVerified, verificationErr := verifyNpmToken(ctx, client, s.getRegistryBaseURL(), value)
			r.Verified = isVerified
			r.SetVerificationError(verificationErr, value)
		}

		results = append(results, r)
	}

	for value := range uniqueAuthMatches {
		r := detectors.Result{
			DetectorType: s.Type(),
			Raw:          []byte(value),
			SecretParts: map[string]string{
				"auth_kind": "auth",
				"key":       value,
			},
			ExtraData: map[string]string{
				"rotation_guide": "https://howtorotate.com/docs/tutorials/npm/",
			},
		}
		// _auth values are opaque/base64 credentials and are not reliably verifiable
		// with a single safe endpoint without assuming decode structure.
		results = append(results, r)
	}

	return results, nil
}

func (s Scanner) IsFalsePositive(result detectors.Result) (bool, string) {
	return detectors.IsKnownFalsePositive(string(result.Raw), detectors.DefaultFalsePositives, true)
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

func (s Scanner) getRegistryBaseURL() string {
	if strings.TrimSpace(s.registryBaseURL) != "" {
		return strings.TrimSpace(s.registryBaseURL)
	}
	return defaultNpmRegistryBaseURL
}

func verifyNpmToken(ctx context.Context, client *http.Client, registryBaseURL, token string) (bool, error) {
	base, err := url.Parse(registryBaseURL)
	if err != nil {
		return false, err
	}
	base.Path = strings.TrimSuffix(base.Path, "/") + "/-/whoami"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base.String(), http.NoBody)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", resp.StatusCode)
	}
}
