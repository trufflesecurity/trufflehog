package common

import (
	"context"
	"fmt"
	"io"
	"net/http"
)

// VerifyBearerToken checks a secret using a read-only endpoint that accepts bearer
// authentication. Only HTTP 200 is considered verified; HTTP 401 is determinately
// invalid, while every other status or transport error is indeterminate.
func VerifyBearerToken(ctx context.Context, client *http.Client, endpoint, key string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+key)

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected bearer-token verification status: %d", resp.StatusCode)
	}
}
