package azure_openai

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	regexp "github.com/wasilibs/go-re2"

	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
)

// Scanner detects API keys for Azure's OpenAI service.
// https://learn.microsoft.com/en-us/azure/ai-services/openai/reference
type Scanner struct {
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	// TODO: Investigate custom `azure-api.net` endpoints.
	// https://github.com/openai/openai-python#microsoft-azure-openai
	azureUrlPat = regexp.MustCompile(`(?i)([a-z0-9-]+\.openai\.azure\.com)`)
	azureKeyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"api[_.-]?key"}) + `\b(?-i:([a-f0-9]{32}))\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{".openai.azure.com"}
}

// FromData will find and optionally verify OpenAI secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	// De-duplicate results.
	tokens := make(map[string]struct{})
	for _, match := range azureKeyPat.FindAllStringSubmatch(dataStr, -1) {
		tokens[match[1]] = struct{}{}
	}
	if len(tokens) == 0 {
		return
	}
	urls := make(map[string]struct{})
	for _, match := range azureUrlPat.FindAllStringSubmatch(dataStr, -1) {
		urls[match[1]] = struct{}{}
	}

	// Process results.
	logCtx := logContext.AddLogger(ctx)
	for token := range tokens {
		s1 := detectors.Result{
			DetectorType: s.Type(),
			Redacted:     token[:3] + "..." + token[25:],
			Raw:          []byte(token),
		}

		for url := range urls {
			if verify {
				client := s.client
				if client == nil {
					client = common.SaneHttpClient()
				}

				isVerified, extraData, verificationErr := verifyAzureToken(logCtx, client, url, token)
				if isVerified || len(urls) == 1 {
					s1.RawV2 = []byte(token + ":" + url)
					s1.Verified = isVerified
					s1.ExtraData = extraData
					s1.SetVerificationError(verificationErr, token)
					break
				}
			}
		}

		results = append(results, s1)
	}
	return
}

func verifyAzureToken(ctx logContext.Context, client *http.Client, baseUrl, token string) (bool, map[string]string, error) {
	// TODO: Replace this with a more suitable long-term endpoint.
	// Most endpoints require additional info, e.g., deployment name, which complicates verification.
	// This may be retired in the future, so we should look for another candidate.
	// https://learn.microsoft.com/en-us/answers/questions/1371786/get-azure-openai-deployments-in-api
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("https://%s/openai/deployments?api-version=2023-03-15-preview", baseUrl), nil)
	if err != nil {
		return false, nil, nil
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("api-key", token)
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
		body, err := io.ReadAll(res.Body)
		if err != nil {
			return false, nil, err
		}

		var deployments deploymentsResponse
		if err := json.Unmarshal(body, &deployments); err != nil {
			if json.Valid(body) {
				return false, nil, fmt.Errorf("failed to decode response %s: %w", req.URL, err)
			} else {
				// If the response isn't JSON it's highly unlikely to be valid.
				return false, nil, nil
			}
		}

		// JSON unmarshal doesn't check whether the structure actually matches.
		if deployments.Object == "" {
			return false, nil, nil
		}

		// No extra data available at the moment.
		return true, nil, nil
	case http.StatusUnauthorized:
		return false, nil, nil
	default:
		return false, nil, fmt.Errorf("unexpected response status %d for %s", res.StatusCode, req.URL)
	}
}

type deploymentsResponse struct {
	Data   []deployment `json:"data"`
	Object string       `json:"object"`
}

type deployment struct {
	ID string `json:"id"`
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_AzureOpenAI
}
