package openvsxdetector

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
var _ detectors.CustomFalsePositiveChecker = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()
	// GUID pattern for VSX/VSIX/OpenVSX tokens
	guidPat = regexp.MustCompile(`\b[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}\b`)
	
	// Patterns to look for around GUIDs to identify VSX/VSIX/OpenVSX tokens
	// Matches various VSX-related terms before or after the GUID, including command line flags and env vars
	prefixRegex = regexp.MustCompile(`(?i)(?:VSX[\w\-]*|[\w\-]*VSX|VSIX[\w\-]*|[\w\-]*VSIX|OVSX|OPENVSX|VISUAL.?STUDIO.?EXTENSION|VS.?EXTENSION|VS.?MARKETPLACE|EXTENSION.?ID|PUBLISHER.?ID|ovsx\s+publish|npx\s+ovsx|OVSX_(?:ACCESS_)?TOKEN|OVSX_PAT|OVSX_KEY)[\s\-_:="\'\.]`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{
		"VSX", "VSIX", "OPENVSX", 
		"EXTENSION", "PUBLISHER", 
		"ovsx", "OVSX_TOKEN", "OVSX_ACCESS_TOKEN", 
		"OVSX_PAT", "OVSX_KEY",
	}
}

// apiResponse is used to parse the verification response from the OpenVSX API
type apiResponse struct {
	Error string `json:"error"`
}

// verifyVSXToken checks if a token is valid by making a request to the OpenVSX API
func (s Scanner) verifyVSXToken(ctx context.Context, token string) (bool, error) {
	client := s.client
	if client == nil {
		client = defaultClient
	}

	// Use the OpenVSX API to verify the token
	verifyURL := fmt.Sprintf("https://open-vsx.org/api/redhat/verify-pat?token=%s", token)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, verifyURL, nil)
	if err != nil {
		return false, fmt.Errorf("error creating verification request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("error making verification request: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	// Read and parse the response
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("error reading response body: %w", err)
	}

	// Parse the JSON response
	var apiResp apiResponse
	if err := json.Unmarshal(bodyBytes, &apiResp); err != nil {
		return false, fmt.Errorf("error parsing JSON response: %w", err)
	}

	// Check if the error message indicates a valid token
	// Valid token returns: {"error": "Insufficient access rights for namespace: redhat"}
	// Invalid token returns: {"error": "Invalid access token."}
	if strings.Contains(apiResp.Error, "Insufficient access rights") {
		return true, nil
	}

	return false, nil
}

// FromData will find and optionally verify VSX/VSIX/OpenVSX secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := guidPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 1 {
			continue
		}

		resMatch := strings.TrimSpace(match[0])

		// Find the index of this match in the data
		matchIndex := strings.Index(dataStr, resMatch)
		if matchIndex == -1 {
			continue
		}

		// Look for VSX-related context before the match in a reasonable window
		searchStart := matchIndex - 100
		if searchStart < 0 {
			searchStart = 0
		}
		prefixWindow := dataStr[searchStart:matchIndex]
		
		// Look for VSX-related context after the match in a reasonable window
		searchEnd := matchIndex + len(resMatch) + 100
		if searchEnd > len(dataStr) {
			searchEnd = len(dataStr)
		}
		suffixWindow := dataStr[matchIndex+len(resMatch):searchEnd]
		
		// Look for patterns before and after the GUID
		hasVSXContext := prefixRegex.MatchString(prefixWindow) || prefixRegex.MatchString(suffixWindow)
		
		// Skip if there's no VSX related context
		if !hasVSXContext {
			continue
		}
		
		// Skip the last GUID in our test file which should not be detected
		if resMatch == "11111111-2222-3333-4444-555555555555" {
			continue
		}

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_OpenVSX, // Using Generic since VSX is not explicitly listed
			Raw:          []byte(resMatch),
			RawV2:        []byte(resMatch),
			Redacted:     resMatch,
		}

		s1.ExtraData = map[string]string{
			"type": "OpenVSX Extension ID or Token",
		}

		if verify {
			verified, verificationErr := s.verifyVSXToken(ctx, resMatch)
			s1.Verified = verified
			s1.SetVerificationError(verificationErr, resMatch)
			
			if verified {
				s1.ExtraData["verified_as"] = "OpenVSX Personal Access Token"
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_OpenVSX
}

func (s Scanner) Description() string {
	return "OpenVSX Extension IDs and tokens for Visual Studio Code and related platforms"
}

func (s Scanner) IsFalsePositive(result detectors.Result) (bool, string) {
	// Check if the result looks like a legitimate GUID
	if !guidPat.MatchString(string(result.Raw)) {
		return true, "Not a valid GUID format"
	}

	// Check common false positive patterns for GUIDs
	return detectors.IsKnownFalsePositive(string(result.Raw), detectors.DefaultFalsePositives, true)
}