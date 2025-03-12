package anthropic

import (
	"context"
	"errors"
	"fmt"
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
	keyPat = regexp.MustCompile(`\b(sk-ant-(?:admin01|api03)-[\w\-]{93}AA)\b`)

	// verification endpoints
	apiKeyEndpoint   = "https://api.anthropic.com/v1/models"
	adminKeyEndpoint = "https://api.anthropic.com/v1/organizations/api_keys"
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"sk-ant-api03", "sk-ant-admin01"}
}

// FromData will find and optionally verify Anthropic secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	keys := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, key := range keys {
		keyMatch := strings.TrimSpace(key[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Anthropic,
			Raw:          []byte(keyMatch),
			ExtraData:    make(map[string]string),
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}

			isAdminKey := isAdminKey(keyMatch)
			var isVerified bool
			var err error

			if isAdminKey {
				isVerified, err = verifyAnthropicKey(ctx, client, adminKeyEndpoint, keyMatch)
				s1.ExtraData["Type"] = "Admin Key"
			} else if !isAdminKey {
				isVerified, err = verifyAnthropicKey(ctx, client, apiKeyEndpoint, keyMatch)
				s1.ExtraData["Type"] = "API Key"
			} else {
				return nil, errors.New("unknown key type detected for anthropic")
			}

			s1.Verified = isVerified
			s1.SetVerificationError(err, keyMatch)

			if s1.Verified {
				s1.AnalysisInfo = map[string]string{
					"key": keyMatch,
				}
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

/*
verifyAnthropicKey verify the anthropic key passed against the endpoint

Endpoints:

  - For api keys: https://docs.anthropic.com/en/api/models-list

  - For admin keys:  https://docs.anthropic.com/en/api/admin-api/apikeys/list-api-keys
*/
func verifyAnthropicKey(ctx context.Context, client *http.Client, endpoint, key string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, http.NoBody)
	if err != nil {
		return false, nil
	}

	req.Header.Set("x-api-key", key)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("anthropic-version", "2023-06-01")

	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer res.Body.Close()

	switch res.StatusCode {
	case http.StatusOK:
		return true, nil

	case http.StatusNotFound, http.StatusUnauthorized:
		// 404 is returned if api key is disabled or not found
		return false, nil

	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Anthropic
}

func (s Scanner) Description() string {
	return "Anthropic is an AI research company. The API keys can be used to access their AI models and services."
}

func isAdminKey(key string) bool {
	return strings.HasPrefix(key, "sk-ant-admin01")
}
