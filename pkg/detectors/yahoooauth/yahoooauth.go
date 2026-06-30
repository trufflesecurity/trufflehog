package yahoooauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	client *http.Client
}

var (
	defaultClient = detectors.DetectorHttpClientWithNoLocalAddresses

	// Yahoo OAuth Access Token pattern
	// Very long tokens (800+ chars) with alphanumeric, dots, underscores, hyphens
	// Example: OfV5iMac7gx6SGNFLAmsFVMTP17EmgpfI4nFJTDaFvHur3Oxg6mVni4LtGltAI_00yW.5EQlHBaU...
	accessTokenPat = regexp.MustCompile(`([A-Za-z0-9][A-Za-z0-9._-]{799,})`)

	// Yahoo OAuth Refresh Token pattern
	// Shorter tokens (60-100 chars) with alphanumeric, dots, underscores, hyphens, tildes
	// Example: AOahQ2qfcSxRRa1r4EDFhCDdsx0y~001~Fj.vO_OAW2IXbqFqc8gK3e0wJdTsx6kulrM-
	refreshTokenPat = regexp.MustCompile(`\b([A-Za-z0-9][A-Za-z0-9._~-]{59,119})\b`)
)

func (s Scanner) Keywords() []string {
	return []string{"yahoo", "oauth", "access_token", "yahoo_token", "yahoooauth"}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})

	// Find access tokens first (very long) - these take priority
	for _, match := range accessTokenPat.FindAllStringSubmatch(dataStr, -1) {
		token := match[1]
		if len(token) >= 800 && len(token) <= 1500 {
			uniqueMatches[token] = struct{}{}
		}
	}

	// Find refresh tokens (shorter) - but skip if already found as part of access token
	for _, match := range refreshTokenPat.FindAllStringSubmatch(dataStr, -1) {
		token := match[1]
		if len(token) >= 60 && len(token) <= 120 {
			// Check if this is a substring of an already-found access token
			isSubstring := false
			for existingToken := range uniqueMatches {
				if strings.Contains(existingToken, token) {
					isSubstring = true
					break
				}
			}
			if !isSubstring {
				uniqueMatches[token] = struct{}{}
			}
		}
	}

	for token := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_YahooOAuth,
			Raw:          []byte(token),
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}

			isVerified, verificationErr := verifyYahooToken(ctx, client, token)
			s1.Verified = isVerified

			if verificationErr != nil {
				s1.SetVerificationError(verificationErr, token)
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

func verifyYahooToken(ctx context.Context, client *http.Client, token string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.login.yahoo.com/openid/v1/userinfo", nil)
	if err != nil {
		return false, err
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return true, nil
		}

		var userInfo map[string]interface{}
		if err := json.Unmarshal(body, &userInfo); err == nil {
			if _, hasEmail := userInfo["email"]; hasEmail {
				return true, nil
			}
			if _, hasSub := userInfo["sub"]; hasSub {
				return true, nil
			}
		}
		return true, nil
	}

	if resp.StatusCode == 401 {
		return false, nil
	}

	return false, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_YahooOAuth
}

func (s Scanner) Description() string {
	return "Yahoo OAuth access tokens are used to authenticate with Yahoo APIs and access user data."
}
