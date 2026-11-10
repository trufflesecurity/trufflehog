package togetherai

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
	// The trailing boundary (?:[^A-Za-z0-9_-]|\z) is used instead of \b so that
	// keys ending in - (a valid base64url character) are still matched.
	keyPat = regexp.MustCompile(`\b(tgp_v1_[A-Za-z0-9_-]{43})(?:[^A-Za-z0-9_-]|\z)`)
)

// Keywords are used for efficiently pre-filtering chunks.
func (s Scanner) Keywords() []string {
	return []string{"tgp_v1_"}
}

// FromData will find and optionally verify Together AI secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	for match := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_TogetherAI,
			Raw:          []byte(match),
			ExtraData: map[string]string{
				"rotation_guide": "https://docs.together.ai/docs/api-keys-authentication",
			},
			SecretParts: map[string]string{"key": match},
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}

			isVerified, extraData, verificationErr := verifyMatch(ctx, client, match)
			s1.Verified = isVerified
			for k, v := range extraData {
				s1.ExtraData[k] = v
			}
			s1.SetVerificationError(verificationErr, match)
		}

		results = append(results, s1)
	}

	return
}

func verifyMatch(ctx context.Context, client *http.Client, token string) (bool, map[string]string, error) {
	// Together AI's OpenAI-compatible models endpoint returns 200 OK for a live
	// key and 401 Unauthorized for an invalid one.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.together.ai/v1/models", nil)
	if err != nil {
		return false, nil, err
	}
	req.Header.Add("Authorization", "Bearer "+token)

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
		return true, nil, nil
	case http.StatusUnauthorized:
		// The key is determinately not live (nothing to do).
		return false, nil, nil
	default:
		return false, nil, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_TogetherAI
}

func (s Scanner) Description() string {
	return "Together AI is an AI inference platform that hosts open-source models. Together AI API keys can be used to access their inference and model management services."
}
