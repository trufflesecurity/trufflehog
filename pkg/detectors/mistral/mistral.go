package mistral

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

	// Mistral AI API keys are 32-character mixed-case alphanumeric strings
	// without a documented prefix. To keep false positives manageable we
	// require the keyword "mistral" to appear within 40 characters of the
	// candidate token (PrefixRegex). The verifier below is the source of
	// truth for whether a match is a real key.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"mistral"}) + `\b([A-Za-z0-9]{32})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
func (s Scanner) Keywords() []string {
	return []string{"mistral"}
}

// FromData will find and optionally verify Mistral secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	for match := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_MistralAI,
			Raw:          []byte(match),
			ExtraData: map[string]string{
				"rotation_guide": "https://docs.mistral.ai/admin/security-access/api-keys/",
			},
			SecretParts: map[string]string{"key": match},
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

func verifyMatch(ctx context.Context, client *http.Client, token string) (bool, error) {
	// https://docs.mistral.ai/api/#tag/models
	// Hitting the models endpoint with a Bearer token returns 200 on a valid
	// key and 401 on an invalid one, with no side effects.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.mistral.ai/v1/models", nil)
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
		// The secret is determinately not verified (nothing to do)
		return false, nil
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_MistralAI
}

func (s Scanner) Description() string {
	return "Mistral AI is a platform that offers large language models through an API. Mistral AI API keys can be used to access these models."
}
