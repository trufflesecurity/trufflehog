package cloudflareapitoken

import (
	"context"
	"fmt"
	"io"
	"net/http"
)

// VerifyUserToken checks if a Cloudflare user API token is valid.
// Returns (true, nil) if verified, (false, nil) for determinate auth
// failures, and (false, err) for indeterminate failures.
func VerifyUserToken(ctx context.Context, client *http.Client, token string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.cloudflare.com/client/v4/user/tokens/verify", nil)
	if err != nil {
		return false, err
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
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

// VerifyAccountToken checks if a Cloudflare account API token is
// valid for the given account ID. Returns (true, nil) if verified,
// (false, nil) for determinate auth failures, and (false, err) for
// indeterminate failures.
func VerifyAccountToken(ctx context.Context, client *http.Client, token, accountID string) (bool, error) {
	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/accounts/%s/tokens/verify", accountID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, err
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
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
