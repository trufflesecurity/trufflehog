package adobeims

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type Scanner struct {
	client *http.Client
}


var _ interface {
	detectors.Detector
	detectors.MaxSecretSizeProvider
} = (*Scanner)(nil)

func (s Scanner) MaxSecretSize() int64 { return 4096 }


var (

	defaultClient = common.SaneHttpClient()

	// Matches any JWT; Adobe IMS tokens are identified by decoding the payload and checking the "as" field.
	jwtPat = regexp.MustCompile(`(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})`)
)


func (s Scanner) Keywords() []string {
	return []string{"eyJ"}
}


func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_AdobeIMS
}


func (s Scanner) Description() string {
	return "Adobe IMS issues OAuth2 tokens for user authentication across Adobe services. Leaked tokens can grant unauthorized access to a user's Adobe account."
}


type jwtPayload struct {
	Type                string `json:"type"`       // "access_token" or "refresh_token"
	ClientID            string `json:"client_id"`
	AuthorizationServer string `json:"as"`         // IMS region, e.g. "ims-na1", "ims-eu1"
}


func decodeJWTPayload(token string) (*jwtPayload, error) {
	// Split the token into three parts: header, payload, signature.
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("not a JWT: expected 3 parts, got %d", len(parts))
	}

	seg := parts[1]
	seg = strings.ReplaceAll(seg, "-", "+")
	seg = strings.ReplaceAll(seg, "_", "/")
	// Add back the '=' padding that base64url omits.
	// base64 strings must have a length that is a multiple of 4.
	switch len(seg) % 4 {
	case 2:
		seg += "=="
	case 3:
		seg += "="
	}

	// Decode the base64 string into raw bytes.
	decoded, err := base64.StdEncoding.DecodeString(seg)
	if err != nil {
		return nil, fmt.Errorf("base64 decode failed: %w", err)
	}

	// Parse the JSON bytes into our jwtPayload struct.
	var payload jwtPayload
	if err := json.Unmarshal(decoded, &payload); err != nil {
		return nil, fmt.Errorf("JSON unmarshal failed: %w", err)
	}
	return &payload, nil
}


func imsBaseURL(as string) string {
	return fmt.Sprintf("https://%s.adobelogin.com", as)
}

func (s Scanner) getClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return defaultClient
}


func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	dataStr := string(data)
	var results []detectors.Result

	// seen prevents the same JWT from being reported twice
	seen := make(map[string]struct{})

	for _, m := range jwtPat.FindAllStringSubmatch(dataStr, -1) {
		tok := m[1]
		if _, ok := seen[tok]; ok {
			continue
		}
		seen[tok] = struct{}{}

		payload, err := decodeJWTPayload(tok)
		if err != nil {
			continue
		}

		// Adobe IMS tokens are identified by the "as" field (e.g. "ims-na1", "ims-eu1").
		if !strings.HasPrefix(payload.AuthorizationServer, "ims-") ||
   payload.ClientID == "" ||
   (payload.Type != "access_token" && payload.Type != "refresh_token") {
			continue
		}

		result := detectors.Result{
			DetectorType: detector_typepb.DetectorType_AdobeIMS,
			Raw:          []byte(tok),
			ExtraData: map[string]string{
				"token_type": payload.Type,
				"client_id":  payload.ClientID,
				"as":         payload.AuthorizationServer,
			},
		}

		if verify {
			client := s.getClient()
			baseURL := imsBaseURL(payload.AuthorizationServer)
			isVerified, verifyErr := validateToken(ctx, client, baseURL, tok, payload)
			result.Verified = isVerified
			result.SetVerificationError(verifyErr, tok)
		}

		results = append(results, result)
	}

	return results, nil
}

// validateToken calls POST /ims/validate_token/v1 to check whether a token is still active.
// It works for both access tokens and refresh tokens.
//
// The request requires:
//   - Authorization: Bearer <token>  (the token itself in the header)
//   - type=<token_type>              (extracted from the JWT payload)
//   - client_id=<client_id>         (extracted from the JWT payload)
//
// Return values:
//   - (true, nil)  — token is valid and active
//   - (false, nil) — token is definitively invalid (expired, revoked, bad signature)
//   - (false, err) — unexpected error (network failure, unexpected HTTP status)
func validateToken(ctx context.Context, client *http.Client, baseURL, token string, payload *jwtPayload) (bool, error) {
	endpoint := baseURL + "/ims/validate_token/v1"

	// Build the POST body as form data: type=access_token&client_id=abc123
	form := url.Values{}
	form.Set("type", payload.Type)
	form.Set("client_id", payload.ClientID)

	// Create the HTTP request with context so it can be cancelled if TruffleHog is stopped
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Send the request to Adobe
	resp, err := client.Do(req)
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		return false, err
	}

	// Read the full response body into memory.
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	switch resp.StatusCode {
	case http.StatusOK:
		var result struct {
			Valid bool `json:"valid"`
		}
		if err := json.Unmarshal(body, &result); err != nil {
			return false, fmt.Errorf("failed to decode validate_token response: %w", err)
		}
		return result.Valid, nil

	case http.StatusUnauthorized, http.StatusForbidden, http.StatusBadRequest:
		return false, nil

	case http.StatusTooManyRequests:
		return false, fmt.Errorf("rate limited by Adobe IMS validate_token")

	default:
		return false, fmt.Errorf("unexpected status %d from validate_token", resp.StatusCode)
	}
}


