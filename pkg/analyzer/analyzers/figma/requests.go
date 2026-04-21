package figma

import (
	"net/http"
)

func callAPIEndpoint(client *http.Client, token string, endpoint endpoint) (*http.Response, error) {
	req, err := http.NewRequest(endpoint.Method, endpoint.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-FIGMA-TOKEN", token)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	return resp, nil
}
