package snowflake

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	// accountIdentifierPat matches Snowflake account identifiers in the format: XXXXXXX-XXXXX
	// Example: ABC1234-EXAMPLE
	accountIdentifierPat = regexp.MustCompile(detectors.PrefixRegex([]string{"account"}) + `\b([a-zA-Z]{7}-[0-9a-zA-Z-_]{1,255}(.privatelink)?)\b`)
	// usernameExclusionPat defines characters that should not be present in usernames
	usernameExclusionPat = `!@#$%^&*{}:<>,.;?()/\+=\s\n`
)

const (
	timeout           = 3 * time.Second
	minPasswordLength = 8
)

// loginRequest represents the payload for Snowflake's login endpoint.
type loginRequest struct {
	Data struct {
		LoginName   string `json:"LOGIN_NAME"`
		Password    string `json:"PASSWORD"`
		AccountName string `json:"ACCOUNT_NAME"`
	} `json:"data"`
}

type loginResponse struct {
	Success bool `json:"success"`
}

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"snowflake"}
}

// meetsSnowflakePasswordRequirements checks if a password meets Snowflake's requirements:
// - Minimum length of 8 characters
// - Contains at least one lowercase letter
// - Contains at least one uppercase letter
// - Contains at least one number
func meetsSnowflakePasswordRequirements(password string) bool {
	if len(password) < minPasswordLength {
		return false
	}

	var hasLower, hasUpper, hasNumber bool
	for _, char := range password {
		switch {
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsNumber(char):
			hasNumber = true
		}

		if hasLower && hasUpper && hasNumber {
			return true
		}
	}

	return false
}

// FromData will find and optionally verify Snowflake secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	// Find all unique account identifiers
	uniqueAccountMatches := make(map[string]struct{})
	for _, match := range accountIdentifierPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueAccountMatches[strings.TrimSpace(match[1])] = struct{}{}
	}

	if len(uniqueAccountMatches) == 0 {
		return nil, nil
	}

	usernameRegexState := common.UsernameRegexCheck(usernameExclusionPat)
	usernameMatches := usernameRegexState.Matches(data)
	if len(usernameMatches) == 0 {
		return nil, nil
	}

	passwordRegexState := common.PasswordRegexCheck(" \r\n") // Exclude spaces, carriage returns, and line feeds
	passwordMatches := passwordRegexState.Matches(data)
	if len(passwordMatches) == 0 {
		return nil, nil
	}

	for resAccountMatch := range uniqueAccountMatches {
		for _, resUsernameMatch := range usernameMatches {
			for _, resPasswordMatch := range passwordMatches {
				metPasswordRequirements := meetsSnowflakePasswordRequirements(resPasswordMatch)
				if !metPasswordRequirements {
					continue
				}

				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_Snowflake,
					Raw:          []byte(resPasswordMatch),
					ExtraData: map[string]string{
						"account":  resAccountMatch,
						"username": resUsernameMatch,
					},
				}

				if !verify {
					results = append(results, s1)
					continue
				}

				verified, err := verifyMatch(ctx, resAccountMatch, resUsernameMatch, resPasswordMatch)
				s1.SetVerificationError(err, resPasswordMatch)
				s1.Verified = verified
				results = append(results, s1)
			}
		}
	}
	return results, nil
}

// verifyMatch attempts to verify a Snowflake credential by making a login request.
func verifyMatch(ctx context.Context, account, username, password string) (bool, error) {
	loginReq := loginRequest{}
	loginReq.Data.LoginName = username
	loginReq.Data.Password = password
	loginReq.Data.AccountName = account

	jsonData, err := json.Marshal(loginReq)
	if err != nil {
		return false, fmt.Errorf("failed to marshal login request: %w", err)
	}

	// Note: This endpoint is undocumented in Snowflake's public API documentation.
	url := fmt.Sprintf("https://%s.snowflakecomputing.com/session/v1/login-request", account)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return false, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Snowflake-Authorization-Token-Type", "BASIC")

	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return false, nil
	}

	var loginResp loginResponse
	if err := json.Unmarshal(body, &loginResp); err != nil {
		return false, fmt.Errorf("failed to parse response: %w", err)
	}

	return loginResp.Success, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Snowflake
}

func (s Scanner) Description() string {
	return "Snowflake is a cloud data platform that provides data warehousing, data lakes, data sharing, and data exchange capabilities. Snowflake credentials can be used to access and manipulate data stored in Snowflake."
}
