package figma

import (
	"net/http"
)

func callAPIEndpoint(client *http.Client, token string, method string, url string) (*http.Response, error) {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-FIGMA-TOKEN", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func callEndpointByScope(client *http.Client, token string, scope Scope) (*http.Response, error) {
	endpoint, err := getScopeEndpoint(scope)
	if err != nil {
		return nil, err
	}

	resp, err := callAPIEndpoint(client, token, endpoint.Method, endpoint.URL)
	if err != nil {
		return nil, err
	}

	return resp, nil
}
