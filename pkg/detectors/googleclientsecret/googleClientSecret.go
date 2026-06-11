package googleclientsecret

import (
	"context"
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
	client    *http.Client
	verifyURL string
}

var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()

	// GOCSPX- prefix followed by exactly 28 base64url-safe characters.
	clientSecretPat = regexp.MustCompile(`\bGOCSPX-([0-9A-Za-z_\-]{28})\b`)

	// Google OAuth client IDs are typically numeric project ID + token + apps domain.
	// Allow mixed-case letters, digits, underscore, and hyphen in the token segment.
	clientIDPat = regexp.MustCompile(`\b([0-9]+-[0-9A-Za-z_-]+\.apps\.googleusercontent\.com)\b`)
)

const defaultVerifyURL = "https://oauth2.googleapis.com/token"

type tokenErrResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func (s Scanner) Keywords() []string {
	// "GOCSPX-" is the only unique keyword for this credential type.
	return []string{"GOCSPX-"}
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_GoogleClientSecret
}

func (s Scanner) Description() string {
	return "Google OAuth2 Client Secrets (GOCSPX- prefix) authenticate server-side OAuth2 flows. " +
		"Exposure allows an attacker to impersonate the registered application and access scoped user data."
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueSecrets := make(map[string]struct{})
	for _, match := range clientSecretPat.FindAllStringSubmatch(dataStr, -1) {
		if len(match) == 2 {
			uniqueSecrets[strings.TrimSpace(match[1])] = struct{}{}
		}
	}

	if len(uniqueSecrets) == 0 {
		return results, nil
	}

	// Extract the first client ID found in this chunk (pairs are rare to repeat).
	var clientID string
	if m := clientIDPat.FindStringSubmatch(dataStr); len(m) == 2 {
		clientID = strings.TrimSpace(m[1])
	}

	client := s.client
	if client == nil {
		client = defaultClient
	}

	for secret := range uniqueSecrets {
		rawSecret := "GOCSPX-" + secret

		r := detectors.Result{
			DetectorType: s.Type(),
			Raw:          []byte(rawSecret),
			SecretParts:  map[string]string{"key": rawSecret},
			ExtraData: map[string]string{
				"rotation_guide": "https://howtorotate.com/docs/tutorials/google/",
			},
		}
		if clientID != "" {
			r.RawV2 = []byte(clientID + ":" + rawSecret)
		}

		if verify {
			isVerified, extraData, verificationErr := verifySecret(ctx, client, s.getVerifyURL(), clientID, rawSecret)
			r.Verified = isVerified
			for k, v := range extraData {
				r.ExtraData[k] = v
			}
			r.SetVerificationError(verificationErr, rawSecret)
		}

		results = append(results, r)
	}

	return results, nil
}

func (s Scanner) getVerifyURL() string {
	if strings.TrimSpace(s.verifyURL) != "" {
		return s.verifyURL
	}
	return defaultVerifyURL
}

// verifySecret posts to Google's OAuth2 token endpoint and interprets the error
// response to determine whether the credentials are genuine.
//
// Google error classification:
//   - invalid_grant / unauthorized_client → credentials are recognised (verified)
//   - invalid_request → some client types trigger this before credential checks (verified)
//   - invalid_client → credentials not recognised (unverified, no error)
//   - anything else → surface as a VerificationError for the caller to handle
func verifySecret(ctx context.Context, client *http.Client, endpointURL, clientID, secret string) (bool, map[string]string, error) {
	if clientID == "" {
		// Placeholder lets Google still evaluate the secret format.
		clientID = "000000000000-placeholder.apps.googleusercontent.com"
	}

	payload := url.Values{}
	payload.Set("client_id", clientID)
	payload.Set("client_secret", secret)
	payload.Set("grant_type", "authorization_code")
	payload.Set("code", "placeholder_code")
	payload.Set("redirect_uri", "http://localhost")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpointURL, strings.NewReader(payload.Encode()))
	if err != nil {
		return false, nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return false, nil, err
	}

	var errResp tokenErrResponse
	if err := json.Unmarshal(body, &errResp); err != nil {
		return false, nil, fmt.Errorf("failed to decode Google token response: %w", err)
	}

	extraData := map[string]string{
		"oauth2_error":             errResp.Error,
		"oauth2_error_description": errResp.ErrorDescription,
	}

	switch resp.StatusCode {
	case http.StatusBadRequest:
		switch errResp.Error {
		case "invalid_grant", "invalid_request":
			// Credentials are known to Google; the grant/request itself is invalid.
			return true, extraData, nil
		case "invalid_client":
			// Google does not recognise this client_id + secret pair.
			return false, extraData, nil
		}
	case http.StatusUnauthorized:
		if errResp.Error == "unauthorized_client" {
			return true, extraData, nil
		}
	}

	return false, extraData, fmt.Errorf(
		"unexpected Google OAuth2 response %d: error=%q description=%q",
		resp.StatusCode, errResp.Error, errResp.ErrorDescription,
	)
}
