package shipmail

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

// GET /organization/access is read-only and accepts any Shipmail API key, whatever its scopes.
// See https://shipmail.to/docs/api/authentication.
const verifyURL = "https://shipmail.to/api/v1/organization/access"

var (
	defaultClient = common.SaneHttpClient()

	// Shipmail API keys: `sm_live_` or `sm_test_`, then 32 random bytes in unpadded base64url.
	keyPat = regexp.MustCompile(`\b(sm_(?:live|test)_[A-Za-z0-9_-]{43})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
func (s Scanner) Keywords() []string {
	return []string{"sm_live_", "sm_test_"}
}

// FromData will find and optionally verify Shipmail secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	for token := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_Shipmail,
			Raw:          []byte(token),
			SecretParts:  map[string]string{"key": token},
		}

		if verify {
			isVerified, verificationErr := verifyMatch(ctx, s.getClient(), token)
			s1.Verified = isVerified
			s1.ExtraData = map[string]string{
				"rotation_guide": "https://shipmail.to/docs/api/authentication",
			}
			s1.SetVerificationError(verificationErr, token)
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

func verifyMatch(ctx context.Context, client *http.Client, token string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, verifyURL, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

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
	case http.StatusForbidden:
		// The key is real but limited to an IP allowlist, so it still works from those addresses.
		return true, nil
	case http.StatusUnauthorized:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_Shipmail
}

func (s Scanner) Description() string {
	return "Shipmail is business email with an API. Shipmail API keys can send email from a customer's domains and read their mailboxes, depending on their scopes."
}
