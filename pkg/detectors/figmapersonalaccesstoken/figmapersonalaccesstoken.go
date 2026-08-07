package figmapersonalaccesstoken

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// VerifyMatch checks if the provided Figma token is valid by making a request to the Figma API.
//
// Tokens are passed via the X-Figma-Token header:
// https://developers.figma.com/docs/rest-api/personal-access-tokens/
//
// Figma documents 400, 403, 404, 429 and 500, and returns 403 for every
// authentication failure: https://developers.figma.com/docs/rest-api/errors/
// We are keeping 401 here for completeness, but it is not documented.
func VerifyMatch(ctx context.Context, client *http.Client, token string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.figma.com/v1/me", http.NoBody)
	if err != nil {
		return false, err
	}

	req.Header.Add("X-Figma-Token", token)
	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	switch res.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized:
		return false, nil
	case http.StatusForbidden:
		return verify403(res.Body)
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

// verify403 distinguishes a dead token from a live one. /v1/me requires the
// current_user:read scope (https://developers.figma.com/docs/rest-api/scopes/),
// so a live token issued without it is rejected with the same 403 as a revoked
// one. The error message is the only thing that separates them.
func verify403(body io.Reader) (bool, error) {
	var res struct {
		Err string `json:"err"`
	}
	if err := json.NewDecoder(body).Decode(&res); err != nil {
		return false, fmt.Errorf("decoding 403 response body: %w", err)
	}

	switch {
	case res.Err == "Invalid token":
		return false, nil
	case strings.HasPrefix(res.Err, "Invalid scope(s):"):
		return true, nil
	default:
		// Reported as indeterminate rather than unverified so an unrecognised
		// message surfaces instead of silently becoming a false negative.
		return false, fmt.Errorf("unexpected 403 response: %q", res.Err)
	}
}
