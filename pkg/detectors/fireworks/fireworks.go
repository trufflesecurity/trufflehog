package fireworks

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
	keyPat        = regexp.MustCompile(`\b(fw_[a-zA-Z0-9]{20,40})\b`)
)

func (s Scanner) Keywords() []string {
	return []string{"fw_"}
}

// FromData will find and optionally verify Fireworks AI secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	for match := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_Fireworks,
			Raw:          []byte(match),
			ExtraData: map[string]string{
				"rotation_guide": "https://docs.fireworks.ai/api-reference/introduction",
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
	// Fireworks AI models list endpoint returns 200 OK on valid keys and 401 Unauthorized on invalid keys.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.fireworks.ai/inference/v1/models", nil)
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
		return false, nil, nil
	default:
		return false, nil, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_Fireworks
}

func (s Scanner) Description() string {
	return "Fireworks AI is an inference platform for generative AI models. Fireworks API keys grant access to hosted model inference and management APIs."
}
