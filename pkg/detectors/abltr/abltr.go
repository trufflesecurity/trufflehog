package abltr

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
	// abltr keys are the prefix `abltr-ai-` followed by 64 lowercase hex characters.
	keyPat = regexp.MustCompile(`\b(abltr-ai-[a-f0-9]{64})\b`)

	verifyEndpoint = "https://api.abltr.ai/v1/models"
)

// Keywords are used for efficiently pre-filtering chunks.
func (s Scanner) Keywords() []string {
	return []string{"abltr-ai-"}
}

// FromData will find and optionally verify abltr secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	keyMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		keyMatches[match[1]] = struct{}{}
	}

	for match := range keyMatches {
		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_Abltr,
			Raw:          []byte(match),
			SecretParts:  map[string]string{"key": match},
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

	return results, nil
}

func verifyMatch(ctx context.Context, client *http.Client, apiKey string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, verifyEndpoint, http.NoBody)
	if err != nil {
		return false, err
	}

	req.Header.Set("Authorization", "Bearer "+apiKey)

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
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
		// 401/403 for an invalid or revoked key; 404 when the key may not list models.
		return false, nil
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_Abltr
}

func (s Scanner) Description() string {
	return "abltr is an OpenAI-compatible inference provider. Its API keys can be used to access hosted models and services."
}
