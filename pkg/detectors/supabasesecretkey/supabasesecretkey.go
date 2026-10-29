package supabasesecretkey

import (
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
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()

	// Secret keys are "sb_secret_" + 22 random base64url characters + "_" + an 8 character base64url checksum.
	// "_" and "-" are part of the key alphabet, so \b can't mark the end of a key that ends in "-".
	// The end is checked in FromData instead. The start isn't: "sb_secret_" is distinctive, and keys often
	// follow an escape sequence such as a literal "\n" in JSON.
	keyPat = regexp.MustCompile(`sb_secret_[A-Za-z0-9_-]{22}_[A-Za-z0-9_-]{8}`)

	// A secret key only works against its own project, and nothing in the key names that project.
	// Verification needs the project URL, https://<project ref>.supabase.co, from the same chunk.
	projectPat = regexp.MustCompile(`\b([a-z0-9]{20})\.supabase\.co\b`)

	// The Supabase CLI gives every local development stack the same secret key, published in
	// supabase/cli (apps/cli-go/pkg/config/apikeys.go). It only works against localhost, so it isn't reported.
	// The prefix is split so secret scanners don't flag this file.
	localDevKey = "sb_" + "secret_N7UND0UgjKTVK-Uodkm0Hg_xSvEMPvz"
)

// Keywords are used for efficiently pre-filtering chunks.
func (s Scanner) Keywords() []string {
	return []string{"sb_secret_"}
}

func isKeyChar(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-'
}

// FromData will find and optionally verify Supabase secret API keys in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueKeys := make(map[string]struct{})
	for _, loc := range keyPat.FindAllStringIndex(dataStr, -1) {
		start, end := loc[0], loc[1]
		// Skip matches followed by more key characters: the string is longer than a secret key.
		if end < len(dataStr) && isKeyChar(dataStr[end]) {
			continue
		}
		if key := dataStr[start:end]; key != localDevKey {
			uniqueKeys[key] = struct{}{}
		}
	}

	uniqueProjects := make(map[string]struct{})
	for _, match := range projectPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueProjects[match[1]] = struct{}{}
	}

	for key := range uniqueKeys {
		if len(uniqueProjects) == 0 {
			s1 := detectors.Result{
				DetectorType: detector_typepb.DetectorType_SupabaseSecretKey,
				Raw:          []byte(key),
				SecretParts:  map[string]string{"key": key},
				ExtraData: map[string]string{
					"rotation_guide": "https://supabase.com/docs/guides/api/api-keys",
				},
			}
			// Without its project the key can't be checked, so it's reported unverified.
			results = append(results, s1)
			continue
		}

		for project := range uniqueProjects {
			url := "https://" + project + ".supabase.co"
			s1 := detectors.Result{
				DetectorType: detector_typepb.DetectorType_SupabaseSecretKey,
				Raw:          []byte(key),
				RawV2:        []byte(key + url),
				SecretParts:  map[string]string{"key": key, "url": url},
				ExtraData: map[string]string{
					"rotation_guide": "https://supabase.com/docs/guides/api/api-keys",
				},
			}

			if verify {
				client := s.client
				if client == nil {
					client = defaultClient
				}

				isVerified, verificationErr := verifyMatch(ctx, client, url, key)
				s1.Verified = isVerified
				s1.SetVerificationError(verificationErr, key)
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

// verifyMatch asks the project's Auth service for its public settings. The API gateway answers 200 when the key
// belongs to the project and 401 when it doesn't. The response body is never read.
// Redirects aren't followed: Go would resend the apikey header to the new location.
func verifyMatch(ctx context.Context, client *http.Client, url, key string) (bool, error) {
	noRedirectClient := *client
	noRedirectClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url+"/auth/v1/settings", nil)
	if err != nil {
		return false, err
	}
	// Supabase reads publishable and secret keys from the apikey header, not Authorization.
	req.Header.Set("apikey", key)

	res, err := noRedirectClient.Do(req)
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

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_SupabaseSecretKey
}

func (s Scanner) Description() string {
	return "Supabase is a hosted Postgres platform. Supabase secret API keys (sb_secret_) give full access to a " +
		"project's data and bypass Row Level Security."
}
