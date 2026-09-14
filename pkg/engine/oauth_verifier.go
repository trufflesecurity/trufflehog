// oauth_verifier.go provides the standalone OAuth2 verification function
// used by the engine scan loop when a detector has a custom verifier with
// OAuth2 auth configured. The function acquires a Bearer token and POSTs
// the detected credential to the custom verifier endpoint.
//
// This file contains only HTTP/verification logic. Configuration state
// (token source, endpoints) lives on EndpointSetter; orchestration lives
// in the engine scan loop.
//
// feature fm-oauth2: custom verifier OAuth2 verification replacement

package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
)

// oauthVerifyRequest is the JSON body sent to the custom verifier
// endpoint. It carries the detected credential and enough metadata
// for the endpoint to decide how to verify it.
type oauthVerifyRequest struct {
	DetectorType string `json:"detector_type"`
	DetectorName string `json:"detector_name,omitempty"`
	RawSecret    string `json:"raw_secret"`
}

// oauthVerifyResponse is the JSON body returned by the custom verifier
// endpoint. The endpoint must return 200 with this structure for both
// verified and not-verified outcomes. Any non-200 status or a missing
// "verified" field is treated as an error.
type oauthVerifyResponse struct {
	Verified bool `json:"verified"`
}

var defaultOAuthHTTPClient = common.SaneHttpClient()

// OAuthVerify acquires a Bearer token from the given TokenSource and
// POSTs the credential to each endpoint until one returns a definitive
// answer. Response protocol:
//
//	200 {"verified": true}   — credential is valid
//	200 {"verified": false}  — credential checked, not valid
//	401                      — token rejected, stop immediately
//	other                    — transient/unexpected, try next endpoint
func OAuthVerify(ctx context.Context, client *http.Client, ts detectors.TokenSource, endpoints []string, result *detectors.Result) (bool, error) {
	if len(endpoints) == 0 {
		return false, fmt.Errorf("no verification endpoints configured")
	}

	if client == nil {
		client = defaultOAuthHTTPClient
	}

	token, err := ts.Token(ctx)
	if err != nil {
		return false, fmt.Errorf("acquiring OAuth2 token for verification: %w", err)
	}

	reqBody := oauthVerifyRequest{
		DetectorType: result.DetectorType.String(),
		DetectorName: result.DetectorName,
		RawSecret:    string(result.Raw),
	}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return false, fmt.Errorf("marshaling verify request: %w", err)
	}

	// Try each endpoint until we get a definitive answer.
	var lastErr error
	var retried bool
	for _, endpoint := range endpoints {
		if common.IsDone(ctx) {
			return false, ctx.Err()
		}

	retryWithNewToken:
		req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(bodyBytes))
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		respBody, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()

		switch resp.StatusCode {
		case http.StatusOK:
			var parsed oauthVerifyResponse
			if err := json.Unmarshal(respBody, &parsed); err != nil {
				lastErr = fmt.Errorf("verifier returned 200 but body is not valid JSON: %w", err)
				continue
			}
			return parsed.Verified, nil
		case http.StatusUnauthorized:
			// Token may have expired. Re-acquire once and retry
			// the same endpoint if we get a different token.
			if !retried {
				retried = true
				newToken, err := ts.Token(ctx)
				if err == nil && newToken != token {
					token = newToken
					goto retryWithNewToken
				}
			}
			return false, fmt.Errorf("OAuth2 token rejected by verifier (401)")
		default:
			lastErr = fmt.Errorf("verifier returned HTTP %d: %s", resp.StatusCode, string(respBody))
		}
	}
	return false, lastErr
}
