package mailkube

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

// GET /mta/v1/api-keys/me describes the key that authenticates the request and
// changes nothing. It runs the same authentication a send runs:
//   - 200 -> the key can send
//   - 403 -> unknown, revoked or regenerated key, or a key used from outside its
//     IP allowlist (the API answers all of them alike)
//
// See https://docs.mailkube.com/api-reference/authentication.
const verifyURL = "https://api.mailkube.com/mta/v1/api-keys/me"

var (
	defaultClient = common.SaneHttpClient()

	// mailkube API keys: `mk_`, a 24-character key id, a 64-character secret and
	// a 33-character issuance tag (a version character, then 32 lowercase hex).
	keyPat = regexp.MustCompile(`\b(mk_[a-z0-9]{24}_[A-Za-z0-9]{64}_[0-9a-z][0-9a-f]{32})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"mk_"}
}

// FromData will find and optionally verify mailkube secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	for token := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_Mailkube,
			Raw:          []byte(token),
			SecretParts:  map[string]string{"key": token},
		}

		if verify {
			client := s.getClient()
			isVerified, extraData, verificationErr := verifyMatch(ctx, client, token)
			s1.Verified = isVerified
			s1.ExtraData = extraData
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

func verifyMatch(ctx context.Context, client *http.Client, token string) (bool, map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, verifyURL, nil)
	if err != nil {
		return false, nil, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Accept", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	switch res.StatusCode {
	case http.StatusOK:
		return true, map[string]string{
			"rotation_guide": "https://docs.mailkube.com/api-reference/authentication",
		}, nil
	case http.StatusForbidden:
		// invalid_api_key: the key does not exist, was revoked or regenerated,
		// or is used from outside its IP allowlist.
		return false, nil, nil
	default:
		// 429 (the endpoint is rate limited per key) and 5xx are indeterminate.
		return false, nil, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_Mailkube
}

func (s Scanner) Description() string {
	return "mailkube is a transactional email API. A mailkube API key can send email from its verified domain and read the key's organization, IP allowlist and plan usage."
}
