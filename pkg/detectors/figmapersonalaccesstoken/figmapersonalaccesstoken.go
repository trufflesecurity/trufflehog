package figmapersonalaccesstoken

import (
	"context"
	"fmt"
	"io"
	"net/http"
)

// VerifyMatch checks if the provided Figma token is valid by making a request to the Figma API.
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
	case http.StatusForbidden:
		return false, nil
		// The Figma API returns 403 for invalid, expired, or revoked tokens,
		// as well as valid tokens that lack the required scopes for the requested resource.
	default:
		return false, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}
