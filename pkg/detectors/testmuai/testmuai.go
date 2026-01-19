package testmuai

import (
	"bytes"
	"context"
	"encoding/json"
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

const verifyURL = "https://auth.lambdatest.com/api/user/token/auth"

var (
	defaultClient = common.SaneHttpClient()

	// Access key pattern: LT_ prefix followed by 47 alphanumeric characters (50 total)
	// Example: LT_abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJK
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{
		"hub.lambdatest.com",
		"testmu",
		"lambdatest",
		"accessKey",
		"access_key",
		"ACCESS_KEY",
		"lambdatestKey",
		"LT_AUTHKEY",
		"LT_ACCESS_KEY",
	}) + `(LT_[a-zA-Z0-9]{47})\b`)

	// Username pattern: alphanumeric characters
	userPat = regexp.MustCompile(detectors.PrefixRegex([]string{
		"hub.lambdatest.com",
		"testmu",
		"lambdatest",
		"userName",
		"username",
		"USER_NAME",
		"lambdatestUser",
		"LT_USERNAME",
		"LAMBDATEST_USERNAME",
	}) + `([a-zA-Z0-9_]{3,50})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
func (s Scanner) Keywords() []string {
	return []string{"LT_"}
}

func (s Scanner) Description() string {
	return "TestMu AI (formerly LambdaTest) is a cloud testing platform that provides browser and app testing infrastructure. TestMu AI credentials (username and access key) can be used to access the testing platform and its APIs."
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}

// FromData will find and optionally verify TestMu AI secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	keyMatches := keyPat.FindAllStringSubmatch(dataStr, -1)
	userMatches := userPat.FindAllStringSubmatch(dataStr, -1)

	// Use a map to deduplicate username:accessKey combinations
	seen := make(map[string]struct{})

	for _, keyMatch := range keyMatches {
		if len(keyMatch) != 2 {
			continue
		}
		accessKey := strings.TrimSpace(keyMatch[1])

		for _, userMatch := range userMatches {
			if len(userMatch) != 2 {
				continue
			}
			username := strings.TrimSpace(userMatch[1])

			// Skip if we've already seen this combination
			combination := username + ":" + accessKey
			if _, exists := seen[combination]; exists {
				continue
			}
			seen[combination] = struct{}{}

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_TestMuAI,
				Raw:          []byte(accessKey),
				RawV2:        []byte(combination),
				Redacted:     username,
			}

			if verify {
				client := s.getClient()
				isVerified, verificationErr := verifyTestMuAI(ctx, client, username, accessKey)
				s1.Verified = isVerified
				s1.SetVerificationError(verificationErr, accessKey)
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

type authRequest struct {
	Username string `json:"username"`
	Token    string `json:"token"`
}

type authResponse struct {
	Type    string `json:"type"`
	Title   string `json:"title"`
	Message string `json:"message"`
}

func verifyTestMuAI(ctx context.Context, client *http.Client, username, accessKey string) (bool, error) {
	reqBody := authRequest{
		Username: username,
		Token:    accessKey,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return false, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, verifyURL, bytes.NewBuffer(jsonBody))
	if err != nil {
		return false, err
	}

	req.Header.Set("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer res.Body.Close()

	switch res.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		// Invalid credentials
		return false, nil
	default:
		var authResp authResponse
		if err := json.NewDecoder(res.Body).Decode(&authResp); err != nil {
			return false, err
		}

		// Check for specific error message indicating invalid credentials
		if authResp.Type == "error" && strings.Contains(authResp.Message, "Access key not present") {
			return false, nil
		}

		return false, nil
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_TestMuAI
}
