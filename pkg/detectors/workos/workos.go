package workos

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	client *http.Client
}

// Ensure the Scanner satisfies the interfaces at compile time.
var (
	_ detectors.Detector                   = (*Scanner)(nil)
	_ detectors.CustomFalsePositiveChecker = (*Scanner)(nil)
)

var (
	defaultClient = common.SaneHttpClient()

	// WorkOS API keys are sk_test_ or sk_live_ followed by base64 of "key_<ULID>,<secret>".
	// "a2V5XzAx" is base64 for "key_01", which separates them from Stripe and Clerk keys that share the prefix.
	keyPat = regexp.MustCompile(`\b(sk_(?:test|live)_a2V5XzAx[A-Za-z0-9+/_-]{60,100}={0,2})(?:[^A-Za-z0-9+/=_-]|$)`)

	decodedPat = regexp.MustCompile(`^(key_[0-9A-Z]{26}),\S{16,}$`)
)

func (s Scanner) Keywords() []string {
	return []string{"sk_test_a2V5XzAx", "sk_live_a2V5XzAx"}
}

// FromData will find and optionally verify WorkOS secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	for match := range uniqueMatches {
		keyID, ok := decodeKeyID(match)
		if !ok {
			continue
		}

		environment := "test"
		if strings.HasPrefix(match, "sk_live_") {
			environment = "live"
		}

		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_WorkOS,
			Raw:          []byte(match),
			SecretParts:  map[string]string{"key": match},
			ExtraData: map[string]string{
				"key_id":      keyID,
				"environment": environment,
			},
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}

			isVerified, verificationErr := verifyMatch(ctx, client, match)
			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr, match)
		}

		results = append(results, s1)
	}

	return
}

// decodeKeyID returns the key ID embedded in a WorkOS API key, and false if the key doesn't decode to the expected shape.
func decodeKeyID(key string) (string, bool) {
	body := strings.TrimRight(key[len("sk_test_"):], "=")
	decoded, err := base64.RawStdEncoding.DecodeString(body)
	if err != nil {
		decoded, err = base64.RawURLEncoding.DecodeString(body)
		if err != nil {
			return "", false
		}
	}

	m := decodedPat.FindStringSubmatch(string(decoded))
	if m == nil {
		return "", false
	}
	return m[1], true
}

func verifyMatch(ctx context.Context, client *http.Client, token string) (bool, error) {
	// Listing at most one organization is read-only. It returns 200 for a valid key and 401 for an invalid one.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.workos.com/organizations?limit=1", nil)
	if err != nil {
		return false, err
	}
	req.Header.Add("Authorization", "Bearer "+token)

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

// IsFalsePositive skips the default wordlist check. Every match has already decoded to a WorkOS key ID, and the
// wordlist would otherwise flag every sk_test_ key because it contains "test".
func (s Scanner) IsFalsePositive(_ detectors.Result) (bool, string) {
	return false, ""
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_WorkOS
}

func (s Scanner) Description() string {
	return "WorkOS provides authentication, SSO, directory sync, and user management APIs. WorkOS API keys grant access to an environment's organizations, users, and connections."
}
