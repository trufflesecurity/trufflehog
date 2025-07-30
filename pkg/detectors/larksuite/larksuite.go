package larksuite

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
)

// Define error code constants for better maintainability
const (
	// Success codes
	CodeSuccess        = 0
	CodeSpecialSuccess = 99991672 // Based on old code - couldn't find documentation for this code

	// HTTP 200 response codes - token invalidity
	CodeInvalidToken      = 20005 // The user access token passed is invalid
	CodeUserNotExist      = 20008 // User not exist
	CodeUserResigned      = 20021 // User resigned
	CodeUserFrozen        = 20022 // User frozen
	CodeUserNotRegistered = 20023 // User not registered

	// Undocumented error codes - these are found in the API responses but not in the documentation
	CodeUndocumentedInvalid1 = 99991663 // Invalid access token for authorization. Please make a request with token attached.
	CodeUndocumentedInvalid2 = 99991668 // Invalid access token for authorization. Please make a request with token attached.
)

// VerificationResult represents the outcome of token verification
type VerificationResult int

const (
	VerificationValid   VerificationResult = iota // Token is valid
	VerificationInvalid                           // Token is definitively invalid
	VerificationError                             // Error occurred during verification
)

type Scanner struct {
	detectors.DefaultMultiPartCredentialProvider
	client *http.Client
}

// Check that the LarkSuite scanner implements the SecretScanner interface at compile time.
var _ detectors.Detector = Scanner{}
var _ detectors.CustomFalsePositiveChecker = (*Scanner)(nil)

type tokenType string

const (
	TenantAccessToken tokenType = "Tenant Access Token"
	UserAccessToken   tokenType = "User Access Token"
	AppAccessToken    tokenType = "App Access Token"
)

var (
	defaultClient = common.SaneHttpClient()
	tokenPats     = map[tokenType]*regexp.Regexp{
		TenantAccessToken: regexp.MustCompile(detectors.PrefixRegex([]string{"lark", "larksuite", "tenant"}) + `(?:^|[^-])\b(t-[a-z0-9A-Z_.]{14,50})\b(?:[^-]|$)`),
		UserAccessToken:   regexp.MustCompile(detectors.PrefixRegex([]string{"lark", "larksuite", "user"}) + `(?:^|[^-])\b(u-[a-z0-9A-Z_.]{14,50})\b(?:[^-]|$)`),
		AppAccessToken:    regexp.MustCompile(detectors.PrefixRegex([]string{"lark", "larksuite", "app"}) + `(?:^|[^-])\b(a-[a-z0-9A-Z_.]{14,50})\b(?:[^-]|$)`),
	}

	verificationUrls = map[tokenType]string{
		TenantAccessToken: "https://open.larksuite.com/open-apis/tenant/v2/tenant/query",
		UserAccessToken:   "https://open.larksuite.com/open-apis/authen/v1/user_info",
		AppAccessToken:    "https://open.larksuite.com/open-apis/calendar/v4/calendars",
	}
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"lark", "larksuite"}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_LarkSuite
}

func (s Scanner) Description() string {
	return "LarkSuite is a collaborative suite that includes chat, calendar, and cloud storage features. The detected token can be used to access and interact with these services."
}

// FromData will find and optionally verify Larksuite secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	for key, tokenPat := range tokenPats {
		uniqueMatches := make(map[string]struct{})
		for _, match := range tokenPat.FindAllStringSubmatch(dataStr, -1) {
			uniqueMatches[match[1]] = struct{}{}
		}

		for token := range uniqueMatches {
			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_LarkSuite,
				Raw:          []byte(token),
			}
			s1.ExtraData = map[string]string{
				"token_type": string(key),
			}
			if verify {
				client := s.client
				if s.client == nil {
					client = defaultClient
				}

				var (
					isVerified bool
					err        error
				)

				isVerified, err = verifyAccessToken(ctx, client, verificationUrls[key], token)
				s1.Verified = isVerified
				s1.SetVerificationError(err, token)
			}

			results = append(results, s1)
		}
	}

	return results, nil
}

func verifyAccessToken(ctx context.Context, client *http.Client, url string, token string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, err
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))

	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	// For LarkSuite API, we expect JSON responses for all documented status codes
	var bodyResponse verificationResponse
	if err := json.NewDecoder(res.Body).Decode(&bodyResponse); err != nil {
		return false, fmt.Errorf("failed to decode response (status %d): %w", res.StatusCode, err)
	}

	// Handle based on error code classification
	result := classifyErrorCode(bodyResponse.Code)

	switch result {
	case VerificationValid:
		return true, nil

	case VerificationInvalid:
		return false, nil

	case VerificationError:
		// All other cases: system errors, rate limits, permission issues, etc.
		// Return error so token is marked as "unverified" (couldn't verify)
		return false, fmt.Errorf("verification failed (status %d, code %d): %s",
			res.StatusCode, bodyResponse.Code, bodyResponse.Message)

	default:
		return false, fmt.Errorf("unexpected status code: %d", res.StatusCode)
	}
}

type verificationResponse struct {
	Code    int    `json:"code"`
	Message string `json:"msg"`
}

// classifyErrorCode determines how to handle different error codes based on their meaning
func classifyErrorCode(code int) VerificationResult {
	// based on the documentation, API fails if response code is not zero
	// https://open.larksuite.com/document/uAjLw4CM/ukTMukTMukTM/reference/authen-v1/user_info/get
	// https://open.larksuite.com/document/server-docs/calendar-v4/calendar/list
	// https://open.larksuite.com/document/server-docs/tenant-v2/tenant/query
	switch code {
	case CodeSuccess, CodeSpecialSuccess:
		return VerificationValid

	// HTTP 200 codes that indicate definitive token invalidity
	case CodeInvalidToken, CodeUserNotExist, CodeUserResigned, CodeUserFrozen, CodeUserNotRegistered, CodeUndocumentedInvalid1,
		CodeUndocumentedInvalid2:
		return VerificationInvalid

	// All other error codes are treated as verification errors
	// This includes:
	// - Invalid requests (20001)
	// - System errors (20050, 190003)
	// - Rate limits (190004, 190005, 190010)
	// - Permission issues (190006, 191002, 191003, 191004, 1184001)
	// - Resource not found (190007, 191000, 195100, 1184000)
	// - Parameter issues (190002, 190008, 190009, 191001)
	default:
		return VerificationError
	}
}

func (s Scanner) IsFalsePositive(result detectors.Result) (bool, string) {
	if _, ok := commonFileExtensions[strings.ToLower(path.Ext(string(result.Raw)))]; ok {
		return ok, ""
	}

	// back to the default false positive checks
	return detectors.IsKnownFalsePositive(string(result.Raw), detectors.DefaultFalsePositives, true)
}

var commonFileExtensions = map[string]struct{}{
	// Web files
	".html": {},
	".htm":  {},
	".css":  {},
	".js":   {},
	".json": {},
	".xml":  {},
	".svg":  {},
	".php":  {},
	".asp":  {},
	".aspx": {},
	".jsp":  {},

	// Document files
	".txt":  {},
	".md":   {},
	".pdf":  {},
	".doc":  {},
	".docx": {},
	".rtf":  {},

	// Data files
	".csv":  {},
	".xlsx": {},
	".xls":  {},
	".sql":  {},
	".db":   {},

	// Config files
	".conf":   {},
	".config": {},
	".ini":    {},
	".yaml":   {},
	".yml":    {},
	".toml":   {},

	// Log files
	".log": {},
	".out": {},
	".err": {},

	// Archive files
	".zip": {},
	".tar": {},
	".gz":  {},
	".rar": {},

	// Image files
	".png":  {},
	".jpg":  {},
	".jpeg": {},
	".gif":  {},
	".bmp":  {},
	".ico":  {},

	// Source code files
	".go":   {},
	".py":   {},
	".java": {},
	".cpp":  {},
	".c":    {},
	".h":    {},
	".rb":   {},
	".rs":   {},
	".ts":   {},

	// Other common files
	".tmp":  {},
	".bak":  {},
	".old":  {},
	".lock": {},
}
