package xai

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

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
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(`\b(xai-[0-9a-zA-Z_]{80})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"xai-"}
}

// FromData will find and optionally verify Xai secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	keyMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		keyMatches[match[1]] = struct{}{}
	}

	for match := range keyMatches {
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_XAI,
			Raw:          []byte(match),
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}

			isVerified, extraData, verificationErr := verifyMatch(ctx, client, match)
			s1.Verified = isVerified
			s1.ExtraData = extraData
			s1.SetVerificationError(verificationErr, match)
		}

		results = append(results, s1)
	}

	return
}

func verifyMatch(ctx context.Context, client *http.Client, apiKey string) (bool, map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.x.ai/v1/api-key", nil)
	if err != nil {
		return false, nil, err
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "Bearer "+apiKey)

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
		// Parse the API response for useful information like name and ACLs
		var data struct {
			Name string   `json:"name"`
			Acls []string `json:"acls"`
		}
		if err := json.NewDecoder(res.Body).Decode(&data); err != nil {
			// The API Key is still verified, but there are parsing errors.
			// Hence, return true for verified along with error.
			return true, nil, fmt.Errorf("failed to decode response: %w", err)
		}

		aclsStr := strings.Join(data.Acls, ",")

		// Convert the relevant fields into a map
		result := map[string]string{
			"name": data.Name,
			"acls": aclsStr,
		}

		return true, result, nil
	case http.StatusBadRequest, http.StatusUnauthorized:
		// The secret is determinately not verified (nothing to do)
		return false, nil, nil
	default:
		return false, nil, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_XAI
}

func (s Scanner) Description() string {
	return "xAI is an AI company with the mission of advancing scientific discovery and gaining a deeper understanding of our universe."
}
