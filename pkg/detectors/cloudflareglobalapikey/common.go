package cloudflareglobalapikey

import (
	"context"
	"fmt"
	"io"
	"net/http"
)

// VerifyGlobalAPIKey checks if a Cloudflare Global API Key is valid.
// Returns (true, nil) if verified, (false, nil) for determinate auth
// failures, and (false, err) for indeterminate failures.
func VerifyGlobalAPIKey(ctx context.Context, client *http.Client, apiKey, email string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.cloudflare.com/client/v4/user", nil)
	if err != nil {
		return false, err
	}
	req.Header.Add("X-Auth-Email", email)
	req.Header.Add("X-Auth-Key", apiKey)
	req.Header.Add("Content-Type", "application/json")

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
	case http.StatusUnauthorized, http.StatusForbidden:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status code: %d", res.StatusCode)
	}
}
