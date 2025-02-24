package launchdarkly

import (
	_ "embed"
	"io"
	"net/http"
)

var (
	baseURL = "https://app.launchdarkly.com/api"

	endpoints = map[string]string{
		"callerIdentity": "/v2/caller-identity",
		"getToken":       "/v2/tokens/%s",
		"getRole":        "/v2/roles/%s",
	}
)

// makeLaunchDarklyRequest send the HTTP GET API request to passed url with passed token and return response body and status code
func makeLaunchDarklyRequest(client *http.Client, endpoint, token string) ([]byte, int, error) {
	// create request
	req, err := http.NewRequest(http.MethodGet, baseURL+endpoint, http.NoBody)
	if err != nil {
		return nil, 0, err
	}

	// add required keys in the header
	req.Header.Set("Authorization", token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}

	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	responseBodyByte, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, err
	}

	return responseBodyByte, resp.StatusCode, nil
}
