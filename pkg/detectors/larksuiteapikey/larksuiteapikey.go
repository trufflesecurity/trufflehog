package larksuiteapikey

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
	detectors.DefaultMultiPartCredentialProvider
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat    = regexp.MustCompile(detectors.PrefixRegex([]string{"lark", "larksuite"}) + `\b(cli_[a-z0-9A-Z]{16})\b`)
	secretPat = regexp.MustCompile(detectors.PrefixRegex([]string{"lark", "larksuite"}) + `\b([a-z0-9A-Z]{32})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"lark", "larksuite", "cli_"}
}

// FromData will find and optionally verify larksuite secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	// find for app id + secrets
	idMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		idMatches[match[1]] = struct{}{}
	}
	secretMatches := make(map[string]struct{})
	for _, match := range secretPat.FindAllStringSubmatch(dataStr, -1) {
		secretMatches[match[1]] = struct{}{}
	}

	for appId := range idMatches {
		for appSecret := range secretMatches {
			resMatch := strings.TrimSpace(appId)
			resSecretMatch := strings.TrimSpace(appSecret)

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_LarkSuiteApiKey,
				Raw:          []byte(resMatch),
				RawV2:        []byte(resMatch + resSecretMatch),
			}

			if verify {
				client := s.client
				if client == nil {
					client = defaultClient
				}
				isVerified, verificationErr := verifyCredentials(ctx, client, resMatch, resSecretMatch)
				s1.Verified = isVerified
				s1.SetVerificationError(verificationErr, resMatch)
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_LarkSuiteApiKey
}

func (s Scanner) Description() string {
	return "LarkSuite is a collaboration platform that provides tools for communication, calendar, and cloud storage. LarkSuite API keys can be used to access and manage these services programmatically."
}

func verifyCredentials(ctx context.Context, client *http.Client, appId, appSecret string) (bool, error) {
	payload := strings.NewReader(fmt.Sprintf(`{"app_id": "%s", "app_secret": "%s"}`, appId, appSecret))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://open.larksuite.com/open-apis/auth/v3/tenant_access_token/internal", payload)
	if err != nil {
		return false, err
	}
	req.Header.Add("Content-Type", "application/json")
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
		var bodyResponse verificationResponse
		if err := json.NewDecoder(res.Body).Decode(&bodyResponse); err != nil {
			err = fmt.Errorf("failed to decode response: %w", err)
			return false, err
		} else {
			if bodyResponse.Code == 0 {
				return true, nil
			} else {
				return false, fmt.Errorf("Verification failed code %d, message %s", bodyResponse.Code, bodyResponse.Message)
			}
		}
	default:
		// 500 larksuite was unable to generate a result
		return false, err
	}
}

type verificationResponse struct {
	Code    int    `json:"code"`
	Message string `json:"msg"`
}
