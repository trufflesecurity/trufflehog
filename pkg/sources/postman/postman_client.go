package postman

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

const (
	GLOBAL_VARS_URL = "https://www.postman.com/_api/workspace/%s/globals"
	//Note: This is an undocumented API endpoint. The office API endpoint keeps returning 502.
	//We'll shift this once that behavior is resolved and stable.
	//Official API Endpoint: "https://api.getpostman.com/workspaces/%s/global-variables"
	WORKSPACE_URL    = "https://api.getpostman.com/workspaces/%s"
	ENVIRONMENTS_URL = "https://api.getpostman.com/environments/%s"
	COLLECTIONS_URL  = "https://api.getpostman.com/collections/%s"

	userAgent     = "PostmanRuntime/7.26.8"
	alt_userAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	//Since we're using the undocumented API endpoint for global vars, we need a different user agent.
	//We'll shift this once that behavior is resolved and stable.
	defaultContentType = "*"
)

// type Collection struct {
// 	Collection struct {
// 		Info struct {
// 			Postman_id  string `json:"_postman_id"`
// 			Name        string `json:"name"`
// 			Description string `json:"description"`
// 			Schema      string `json:"schema"`
// 			UpdatedAt   string `json:"updatedAt"`
// 			Uid         string `json:"uid"`
// 		} `json:"info"`
// 		Item     []interface{} `json:"item"`
// 		Auth     interface{}   `json:"auth"`
// 		Variable []interface{} `json:"variable"`
// 		Event    []interface{} `json:"event"`
// 	} `json:"collection"`
// }

// A Client manages communication with the Postman API.
type Client struct {
	// HTTP client used to communicate with the API
	HTTPClient *http.Client

	// Headers to attach to every requests made with the client.
	Headers map[string]string

	// URL for API request
	URL *url.URL
}

// NewClient returns a new Postman API client.
func NewClient(postmanToken string) *Client {
	bh := map[string]string{
		"Content-Type": defaultContentType,
		"User-Agent":   userAgent,
		"X-API-Key":    postmanToken,
	}

	c := &Client{
		HTTPClient: http.DefaultClient,
		Headers:    bh,
	}

	return c
}

// NewRequest creates an API request (Only GET needed for our interaction w/ Postman)
// If specified, the map provided by headers will be used to update request headers.
func (c *Client) NewRequest(urlStr string, headers map[string]string) (*http.Request, error) {
	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		return nil, err
	}

	var h = c.Headers
	if headers != nil {
		for k, v := range headers {
			h[k] = v
		}
	}

	for k, v := range h {
		req.Header.Set(k, v)
	}

	return req, nil
}

// checkResponse checks the API response for errors and returns them if present.
// A Response is considered an error if it has a status code outside the 2XX range.
func checkResponseStatus(r *http.Response) error {
	if c := r.StatusCode; 200 <= c && c <= 299 {
		return nil
	}
	return fmt.Errorf("Postman Request failed with status code: %d", r.StatusCode)
}

// parseResponseJSON parses the JSON response from the API.
func parseResponseJSON(r *http.Response) (map[string]interface{}, error) {
	//Consider using structs for this instead of just assigning to a map
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	data := make(map[string]interface{})

	// Parse the JSON data into a map
	err = json.Unmarshal(body, &data)
	if err != nil {
		fmt.Println("Error:", err)
		return nil, err
	}
	return data, nil
}

// postmanDo sends an API request and returns the API response after checking for errors.
func (c *Client) postmanDo(req *http.Request) (*http.Response, error) {
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}

	if err := checkResponseStatus(resp); err != nil {
		return nil, err
	}

	return resp, nil
}

// GetGlobals returns the global variables for a given workspace
func (c *Client) GetGlobals(workspace_uuid string) (map[string]interface{}, error) {
	url := fmt.Sprintf(GLOBAL_VARS_URL, workspace_uuid)
	req, err := c.NewRequest(url, map[string]string{"User-Agent": alt_userAgent})
	if err != nil {
		return nil, err
	}
	resp, err := c.postmanDo(req)
	if err != nil {
		return nil, err
	}
	json, err := parseResponseJSON(resp)
	if err != nil {
		return nil, err
	}
	return json, nil
}

// GetEnvironment returns the environment variables for a given environment
func (c *Client) GetEnvironment(environment_uuid string) (map[string]interface{}, error) {
	url := fmt.Sprintf(ENVIRONMENTS_URL, environment_uuid)
	req, err := c.NewRequest(url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.postmanDo(req)
	if err != nil {
		return nil, err
	}
	json, err := parseResponseJSON(resp)
	if err != nil {
		return nil, err
	}
	return json, nil
}

// GetCollection returns the collection for a given collection
func (c *Client) GetCollection(collection_uuid string) (map[string]interface{}, error) {
	url := fmt.Sprintf(COLLECTIONS_URL, collection_uuid)
	req, err := c.NewRequest(url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.postmanDo(req)
	if err != nil {
		return nil, err
	}
	json, err := parseResponseJSON(resp)
	if err != nil {
		return nil, err
	}
	return json, nil
}

// GetWorkspace returns the workspace for a given workspace
func (c *Client) GetWorkspace(workspace_uuid string) (map[string]interface{}, error) {
	url := fmt.Sprintf(WORKSPACE_URL, workspace_uuid)
	req, err := c.NewRequest(url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.postmanDo(req)
	if err != nil {
		return nil, err
	}
	json, err := parseResponseJSON(resp)
	if err != nil {
		return nil, err
	}
	return json, nil

}
