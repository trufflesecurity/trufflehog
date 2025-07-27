package api_token

import (
	"context"
	"fmt"
	"io"
	"net/http"

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
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"make"}) + `\b([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\b`)
	// Pattern to match Make.com URLs in the data
	urlPat = regexp.MustCompile(`\bhttps://(eu[12]|us[12])\.make\.(?:com|celonis\.com)/api/v2/`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"make"}
}

// FromData will find and optionally verify Make secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	// Extract Make URLs from the data
	var foundURLs []string
	for _, match := range urlPat.FindAllStringSubmatch(dataStr, -1) {
		foundURLs = append(foundURLs, match[0])
	}

	// If URLs were found, create combinations of tokens and URLs
	if len(foundURLs) > 0 {
		for match := range uniqueMatches {
			for _, foundURL := range foundURLs {
				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_MakeApiToken,
					Raw:          []byte(match),
					RawV2:        []byte(match + ":" + foundURL),
				}

				if verify {
					client := s.client
					if client == nil {
						client = defaultClient
					}

					isVerified, extraData, verificationErr := verifyMatch(ctx, client, match, foundURLs)
					s1.Verified = isVerified
					s1.ExtraData = extraData
					s1.SetVerificationError(verificationErr, match)
				}

				results = append(results, s1)
			}
		}
	} else {
		// No URLs found, just return tokens
		for match := range uniqueMatches {
			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_MakeApiToken,
				Raw:          []byte(match),
			}

			if verify {
				client := s.client
				if client == nil {
					client = defaultClient
				}

				isVerified, extraData, verificationErr := verifyMatch(ctx, client, match, foundURLs)
				s1.Verified = isVerified
				s1.ExtraData = extraData
				s1.SetVerificationError(verificationErr, match)
			}

			results = append(results, s1)
		}
	}

	return
}

func verifyMatch(ctx context.Context, client *http.Client, token string, foundURLs []string) (bool, map[string]string, error) {
	baseURLs := []string{
		"https://eu1.make.com/api/v2/",
		"https://eu2.make.com/api/v2/",
		"https://us1.make.com/api/v2/",
		"https://us2.make.com/api/v2/",
		"https://us1.make.celonis.com/api/v2/",
		"https://eu1.make.celonis.com/api/v2/",
	}


	// If we found URLs in the data, try those first
	if len(foundURLs) > 0 {
		for _, foundURL := range foundURLs {
			verified, err := tryURL(ctx, client, foundURL, token)
			if verified {
				return true, nil, nil
			}
			if err != nil {
				// If the matched URL failed, continue to try all base URLs
				break
			}
			// If the matched URL returned a determinate failure (401), we still try other base URLs
		}
	}

	// Try all base URLs
	var lastErr error
	for _, baseURL := range baseURLs {
		verified, err := tryURL(ctx, client, baseURL, token)
		if verified {
			return true, nil, nil
		}
		if err != nil {
			lastErr = err
			continue
		}
		// Continue to next URL on determinate failures (401)
	}

	// If we got here, either all endpoints failed or we had errors
	if lastErr != nil {
		return false, nil, lastErr
	}
	return false, nil, nil
}

func tryURL(ctx context.Context, client *http.Client, baseURL, token string) (bool, error) {
	// This endpoint returns 200 OK if the token is valid and the correct FQDN for the API is used.
	// https://developers.make.com/api-documentation/api-reference/users-greater-than-me#get-users-me-current-authorization
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"users/me/current-authorization", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Token "+token)

	res, err := client.Do(req)
	if err != nil {
		return false, err
	}

	func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	switch res.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized:
		// Determinate failure - invalid token
		return false, nil
	default:
		// Indeterminate failure - unexpected response
		return false, fmt.Errorf("unexpected status code: %d", res.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_MakeApiToken
}

func (s Scanner) Description() string {
	return "Make.com is a low-code/no-code automation platform that allows users to connect apps and services typically to automate business workflows. This detector identifies API tokens used for Make.com integrations."
}
