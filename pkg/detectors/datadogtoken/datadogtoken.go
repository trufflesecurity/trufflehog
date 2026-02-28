package datadogtoken

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"
	"unicode"

	regexp2 "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	detectors.EndpointSetter
	detectors.DefaultMultiPartCredentialProvider
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)
var _ detectors.EndpointCustomizer = (*Scanner)(nil)
var _ detectors.CloudProvider = (*Scanner)(nil)

func (Scanner) CloudEndpoint() string { return "https://api.datadoghq.com" }

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	appPat = regexp2.MustCompile(detectors.PrefixRegex([]string{"datadog", "dd"}) + `\b([a-zA-Z-0-9]{40})\b`)
	apiPat = regexp2.MustCompile(detectors.PrefixRegex([]string{"datadog", "dd"}) + `\b([a-zA-Z-0-9]{32})\b`)

	// False positive detection patterns
	npmIntegrityPat     = regexp.MustCompile(`sha(256|384|512|1)-[A-Za-z0-9+/=]+`)
	goModuleChecksumPat = regexp.MustCompile(`h[0-9]+:[A-Za-z0-9+/=]+=`)
	urlEncodedPathPat   = regexp.MustCompile(`%3[Aa]|https?://[^\s]+`)
	sopsEncryptedPat    = regexp.MustCompile(`ENC\[AES256_GCM,data:[A-Za-z0-9+/=]+`)
)

type userServiceResponse struct {
	Data     []*user    `json:"data"`
	Included []*options `json:"included"`
}

type user struct {
	Attributes userAttributes `json:"attributes"`
}

type userAttributes struct {
	Email            string `json:"email"`
	IsServiceAccount bool   `json:"service_account"`
	Verified         bool   `json:"verified"`
	Disabled         bool   `json:"disabled"`
}

type options struct {
	Type       string          `json:"type"`
	Attributes optionAttribute `json:"attributes"`
}

type optionAttribute struct {
	Url      string `json:"url"`
	Name     string `json:"name"`
	Disabled bool   `json:"disabled"`
}

func setUserEmails(data []*user, s1 *detectors.Result) {
	var emails []string
	for _, user := range data {
		// filter out non verified emails, disabled emails, service accounts
		if user.Attributes.Verified && !user.Attributes.Disabled && !user.Attributes.IsServiceAccount {
			emails = append(emails, user.Attributes.Email)
		}
	}

	if len(emails) == 0 && len(data) > 0 {
		emails = append(emails, data[0].Attributes.Email)
	}

	s1.ExtraData["user_emails"] = strings.Join(emails, ", ")
}

func setOrganizationInfo(opt []*options, s1 *detectors.Result) {
	var orgs *options
	for _, option := range opt {
		if option.Type == "orgs" && !option.Attributes.Disabled {
			orgs = option
			break
		}
	}

	if orgs != nil {
		s1.ExtraData["org_name"] = orgs.Attributes.Name
		s1.ExtraData["org_url"] = orgs.Attributes.Url
	}

}

// hasDigit checks if a string contains at least one digit.
func hasDigit(s string) bool {
	for _, r := range s {
		if unicode.IsDigit(r) {
			return true
		}
	}
	return false
}

// isNpmIntegrityHash checks if a match is part of an npm package integrity hash.
// Pattern: "integrity": "sha512-...==" or sha256-/sha384-/sha1-
func isNpmIntegrityHash(dataStr string, match string, startIdx, endIdx int) bool {
	// Extract context around the match (±200 chars or to line boundaries)
	contextStart := startIdx - 200
	if contextStart < 0 {
		contextStart = 0
	}
	contextEnd := endIdx + 200
	if contextEnd > len(dataStr) {
		contextEnd = len(dataStr)
	}
	context := dataStr[contextStart:contextEnd]

	// Check if match is preceded by sha*- and followed by == or =
	if npmIntegrityPat.MatchString(context) {
		// Check if the match is within an integrity hash pattern
		matchPos := strings.Index(context, match)
		if matchPos > 0 {
			beforeMatch := context[:matchPos]
			afterMatch := context[matchPos+len(match):]
			// Check for sha*- prefix and ==/= suffix
			if (strings.Contains(beforeMatch, "sha512-") || strings.Contains(beforeMatch, "sha256-") ||
				strings.Contains(beforeMatch, "sha384-") || strings.Contains(beforeMatch, "sha1-")) &&
				(strings.HasPrefix(afterMatch, "==") || strings.HasPrefix(afterMatch, "=")) {
				return true
			}
		}
	}
	return false
}

// isGoModuleChecksum checks if a match is part of a Go module checksum.
// Pattern: h1:...= or go.mod h1:...=
func isGoModuleChecksum(dataStr string, match string, startIdx, endIdx int) bool {
	// Extract context around the match (±200 chars or to line boundaries)
	contextStart := startIdx - 200
	if contextStart < 0 {
		contextStart = 0
	}
	contextEnd := endIdx + 200
	if contextEnd > len(dataStr) {
		contextEnd = len(dataStr)
	}
	context := dataStr[contextStart:contextEnd]

	// Check if match is preceded by h1: (or h2:, h3:, etc.) and followed by =
	if goModuleChecksumPat.MatchString(context) {
		matchPos := strings.Index(context, match)
		if matchPos > 0 {
			beforeMatch := context[:matchPos]
			afterMatch := context[matchPos+len(match):]
			// Check for h1:/h2:/h3: prefix and = suffix
			if (strings.Contains(beforeMatch, "h1:") || strings.Contains(beforeMatch, "h2:") ||
				strings.Contains(beforeMatch, "h3:") || strings.Contains(beforeMatch, "go.mod")) &&
				strings.HasPrefix(afterMatch, "=") {
				return true
			}
		}
	}
	return false
}

// isUrlEncodedPath checks if a match is part of a URL-encoded path.
// Pattern: Contains %3A (URL-encoded colon) or is within a URL
func isUrlEncodedPath(dataStr string, match string, startIdx, endIdx int) bool {
	// Extract context around the match (±200 chars or to line boundaries)
	contextStart := startIdx - 200
	if contextStart < 0 {
		contextStart = 0
	}
	contextEnd := endIdx + 200
	if contextEnd > len(dataStr) {
		contextEnd = len(dataStr)
	}
	context := dataStr[contextStart:contextEnd]

	// Check if context contains URL-encoded patterns or URL structure
	if strings.Contains(context, "%3A") || strings.Contains(context, "%3a") {
		return true
	}
	// Check if it's within a URL pattern
	if urlEncodedPathPat.MatchString(context) {
		matchPos := strings.Index(context, match)
		if matchPos > 0 {
			beforeMatch := context[:matchPos]
			// Check if there's a URL pattern before the match
			if strings.Contains(beforeMatch, "http://") || strings.Contains(beforeMatch, "https://") ||
				strings.Contains(beforeMatch, "app.datadoghq.com") {
				return true
			}
		}
	}
	return false
}

// isSopsEncrypted checks if a match is part of SOPS-encrypted data.
// Pattern: ENC[AES256_GCM,data:...] or similar SOPS encryption patterns
func isSopsEncrypted(dataStr string, match string, startIdx, endIdx int) bool {
	// Extract context around the match (±200 chars or to line boundaries)
	contextStart := startIdx - 200
	if contextStart < 0 {
		contextStart = 0
	}
	contextEnd := endIdx + 200
	if contextEnd > len(dataStr) {
		contextEnd = len(dataStr)
	}
	context := dataStr[contextStart:contextEnd]

	// Check if context contains SOPS encryption pattern
	if sopsEncryptedPat.MatchString(context) {
		matchPos := strings.Index(context, match)
		if matchPos > 0 {
			beforeMatch := context[:matchPos]
			// Check if match is within ENC[...] pattern
			if strings.Contains(beforeMatch, "ENC[") || strings.Contains(beforeMatch, "data:") {
				return true
			}
		}
	}
	return false
}

// isRepeatedCharacter checks if a string consists of the same character repeated.
// This filters out test/placeholder values like "11111111111111111111111111111111"
func isRepeatedCharacter(s string) bool {
	if len(s) == 0 {
		return false
	}
	firstChar := s[0]
	for i := 1; i < len(s); i++ {
		if s[i] != firstChar {
			return false
		}
	}
	return true
}

// isBase64Certificate checks if a match is part of a base64-encoded certificate.
// Pattern: caBundle, certificate fields, or -----BEGIN CERTIFICATE----- markers
// Note: Match might be from BASE64-decoded content, so we check the original dataStr context
func isBase64Certificate(dataStr string, match string, startIdx, endIdx int) bool {
	// Extract larger context around the match (±2000 chars to catch certificate fields)
	contextStart := startIdx - 2000
	if contextStart < 0 {
		contextStart = 0
	}
	contextEnd := endIdx + 2000
	if contextEnd > len(dataStr) {
		contextEnd = len(dataStr)
	}
	context := dataStr[contextStart:contextEnd]

	// Check if context contains certificate-related keywords (check both original and decoded contexts)
	certKeywords := []string{
		"caBundle",
		"caBundle:",
		"certificate",
		"cert:",
		"-----BEGIN CERTIFICATE-----",
		"-----END CERTIFICATE-----",
		"BEGIN CERTIFICATE",
		"END CERTIFICATE",
		"LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t", // Base64 of "-----BEGIN CERTIFICATE-----"
	}

	for _, keyword := range certKeywords {
		if strings.Contains(context, keyword) {
			// Find all occurrences of the keyword
			keywordPos := strings.Index(context, keyword)
			matchPosInContext := startIdx - contextStart

			// If keyword appears before the match, check distance
			if keywordPos >= 0 && keywordPos < matchPosInContext {
				// Check if match is within reasonable distance (within 1500 chars)
				if matchPosInContext-keywordPos < 1500 {
					return true
				}
			}
			// Also check if keyword appears after match (certificate might span the match)
			if keywordPos >= 0 && keywordPos > matchPosInContext {
				if keywordPos-matchPosInContext < 1500 {
					return true
				}
			}
		}
	}

	return false
}

// isLikelyFalsePositive checks if a matched string is likely a false positive.
func isLikelyFalsePositive(dataStr string, match string, startIdx, endIdx int) bool {
	// Filter 1: Only letters (no digits) - likely service names/identifiers
	if !hasDigit(match) {
		return true
	}

	// Filter 2: Repeated characters (test/placeholder values like "11111111111111111111111111111111")
	if isRepeatedCharacter(match) {
		return true
	}

	// Filter 3: NPM integrity hash
	if isNpmIntegrityHash(dataStr, match, startIdx, endIdx) {
		return true
	}

	// Filter 4: Go module checksum
	if isGoModuleChecksum(dataStr, match, startIdx, endIdx) {
		return true
	}

	// Filter 5: URL-encoded path
	if isUrlEncodedPath(dataStr, match, startIdx, endIdx) {
		return true
	}

	// Filter 6: SOPS-encrypted data
	if isSopsEncrypted(dataStr, match, startIdx, endIdx) {
		return true
	}

	// Filter 7: Base64-encoded certificate
	if isBase64Certificate(dataStr, match, startIdx, endIdx) {
		return true
	}

	return false
}

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"datadog"}
}

// FromData will find and optionally verify DatadogToken secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	appMatches := appPat.FindAllStringSubmatchIndex(dataStr, -1)
	apiMatches := apiPat.FindAllStringSubmatchIndex(dataStr, -1)

	for _, apiMatchIdx := range apiMatches {
		if len(apiMatchIdx) < 4 {
			continue
		}
		resApiMatch := strings.TrimSpace(dataStr[apiMatchIdx[2]:apiMatchIdx[3]])

		// Filter out false positives for API key
		if isLikelyFalsePositive(dataStr, resApiMatch, apiMatchIdx[2], apiMatchIdx[3]) {
			continue
		}

		appIncluded := false
		for _, appMatchIdx := range appMatches {
			if len(appMatchIdx) < 4 {
				continue
			}
			resAppMatch := strings.TrimSpace(dataStr[appMatchIdx[2]:appMatchIdx[3]])

			// Filter out false positives for Application key
			if isLikelyFalsePositive(dataStr, resAppMatch, appMatchIdx[2], appMatchIdx[3]) {
				continue
			}

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_DatadogToken,
				Raw:          []byte(resAppMatch),
				RawV2:        []byte(resAppMatch + resApiMatch),
				ExtraData: map[string]string{
					"Type": "Application+APIKey",
				},
			}

			if verify {
				for _, baseURL := range s.Endpoints() {
					req, err := http.NewRequestWithContext(ctx, "GET", baseURL+"/api/v2/users", nil)
					if err != nil {
						continue
					}
					req.Header.Add("Content-Type", "application/json")
					req.Header.Add("DD-API-KEY", resApiMatch)
					req.Header.Add("DD-APPLICATION-KEY", resAppMatch)
					res, err := client.Do(req)
					if err == nil {
						defer func() {
							_, _ = io.Copy(io.Discard, res.Body)
							_ = res.Body.Close()
						}()
						if res.StatusCode >= 200 && res.StatusCode < 300 {
							s1.Verified = true
							s1.AnalysisInfo = map[string]string{"apiKey": resApiMatch, "appKey": resAppMatch}
							var serviceResponse userServiceResponse
							if err := json.NewDecoder(res.Body).Decode(&serviceResponse); err == nil {
								// setup emails
								if len(serviceResponse.Data) > 0 {
									setUserEmails(serviceResponse.Data, &s1)
								}
								// setup organizations
								if len(serviceResponse.Included) > 0 {
									setOrganizationInfo(serviceResponse.Included, &s1)
								}
							}
						}
					}
				}
			}
			appIncluded = true
			results = append(results, s1)
		}

		if !appIncluded {
			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_DatadogToken,
				Raw:          []byte(resApiMatch),
				RawV2:        []byte(resApiMatch),
				ExtraData: map[string]string{
					"Type": "APIKeyOnly",
				},
			}

			if verify {
				for _, baseURL := range s.Endpoints() {
					req, err := http.NewRequestWithContext(ctx, "GET", baseURL+"/api/v1/validate", nil)
					if err != nil {
						continue
					}
					req.Header.Add("Content-Type", "application/json")
					req.Header.Add("DD-API-KEY", resApiMatch)
					res, err := client.Do(req)
					if err == nil {
						defer func() {
							_, _ = io.Copy(io.Discard, res.Body)
							_ = res.Body.Close()
						}()
						if res.StatusCode >= 200 && res.StatusCode < 300 {
							s1.Verified = true
							s1.AnalysisInfo = map[string]string{"apiKey": resApiMatch}
						}
					}
				}
			}
			results = append(results, s1)
		}
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_DatadogToken
}

func (s Scanner) Description() string {
	return "Datadog is a monitoring and security platform for cloud applications. Datadog API and Application keys can be used to access and manage data and configurations within Datadog."
}
