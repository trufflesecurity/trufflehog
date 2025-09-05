package kontent

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	apiKeyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"kontent"}) + common.BuildRegexJWT("30,34", "200,400", "40,43"))
	envIDPat  = regexp.MustCompile(detectors.PrefixRegex([]string{"kontent", "env"}) + common.UUIDPattern)

	// API return this error when the environment does not exist or the api key does not have the permission to access that environment
	envErr = "The specified API key does not provide the permissions required to access the environment"
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"kontent"}
}

// FromData will find and optionally verify Kontent secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	var uniqueAPIKeys, uniqueEnvIDs = make(map[string]struct{}), make(map[string]struct{})

	for _, apiKey := range apiKeyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueAPIKeys[apiKey[1]] = struct{}{}
	}

	for _, envID := range envIDPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueEnvIDs[envID[1]] = struct{}{}
	}

	for envID := range uniqueEnvIDs {
		if _, ok := detectors.UuidFalsePositives[detectors.FalsePositive(envID)]; ok {
			continue
		}

		if detectors.StringShannonEntropy(envID) < 3 {
			continue
		}

		for apiKey := range uniqueAPIKeys {
			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Kontent,
				Raw:          []byte(envID),
				RawV2:        []byte(envID + apiKey),
			}

			if verify {
				isVerified, verificationErr := verifyKontentAPIKey(client, envID, apiKey)
				s1.Verified = isVerified
				s1.SetVerificationError(verificationErr)
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Kontent
}

func (s Scanner) Description() string {
	return "Kontent is a headless CMS (Content Management System) that allows users to manage and deliver content to any device or application. Kontent API keys can be used to access and manage this content."
}

// api docs: https://kontent.ai/learn/docs/apis/openapi/management-api-v2/#operation/retrieve-environment-information
func verifyKontentAPIKey(client *http.Client, envID, apiKey string) (bool, error) {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://manage.kontent.ai/v2/projects/%s", envID), nil)
	if err != nil {
		return false, nil
	}

	req.Header.Add("Authorization", "Bearer "+apiKey)

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}

	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusForbidden:
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return false, err
		}

		if strings.Contains(string(bodyBytes), envErr) {
			return true, nil
		}

		return false, nil
	case http.StatusUnauthorized:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}
