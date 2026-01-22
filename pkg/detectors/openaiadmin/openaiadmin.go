package openaiadmin

import (
	"context"
	"fmt"
	"io"
	"net/http"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()

	// Admin keys follow the format: sk-admin-{58 chars}T3BlbkFJ{58 chars}
	// Total length: 133 chars (9 char prefix + 124 chars for key)
	// where T3BlbkFJ is the base64-encoded string: OpenAI
	keyPat = regexp.MustCompile(`\b(sk-admin-[A-Za-z0-9_-]{58}T3BlbkFJ[A-Za-z0-9_-]{58})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
func (s Scanner) Keywords() []string {
	// Using both keywords for better detection coverage
	// T3BlbkFJ is the OpenAI signature, sk-admin- is the specific prefix
	return []string{"T3BlbkFJ", "sk-admin-"}
}

// FromData will find and optionally verify Openaiadmin secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	for token := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_OpenAIAdmin,
			Redacted:     token[:11] + "..." + token[len(token)-4:],
			Raw:          []byte(token),
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}

			isVerified, verificationErr := verifyMatch(ctx, client, token)
			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr, token)
			s1.AnalysisInfo = map[string]string{
				"key": token,
			}
		}

		results = append(results, s1)
	}

	return
}

func verifyMatch(ctx context.Context, client *http.Client, token string) (bool, error) {
	// Use the Admin API Keys list endpoint to verify the admin key
	// https://platform.openai.com/docs/api-reference/admin-api-keys/list
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.openai.com/v1/organization/admin_api_keys", http.NoBody)
	if err != nil {
		return false, err
	}

	req.Header.Set("Content-Type", "application/json")
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
	case http.StatusUnauthorized:
		// Invalid admin key - determinate failure
		return false, nil
	default:
		// Unexpected response - indeterminate failure
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_OpenAIAdmin
}

func (s Scanner) Description() string {
	return "OpenAI Admin API keys provide administrative access to OpenAI organization resources. These keys can be used to manage API keys, audit logs, and other organization-level settings."
}
