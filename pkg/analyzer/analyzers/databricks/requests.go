package databricks

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

var (
	apiEndpoints = map[ResourceType]string{
		CurrentUser: "/api/2.0/preview/scim/v2/Me",
	}
)

// makeDataBricksRequest send the API request to passed url with passed key as access token and return response body and status code
func makeDataBricksRequest(client *http.Client, endpoint, key string) ([]byte, int, error) {
	// create request
	req, err := http.NewRequest(http.MethodGet, endpoint, http.NoBody)
	if err != nil {
		return nil, 0, err
	}

	// add key in the header
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", key))

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

func captureUserInfo(client *http.Client, domain, key string, secretInfo *SecretInfo) error {
	respBody, statusCode, err := makeDataBricksRequest(client, domain+apiEndpoints[CurrentUser], key)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var user CurrentUserInfo

		if err := json.Unmarshal(respBody, &user); err != nil {
			return err
		}

		secretInfo.UserInfo = User{
			ID:       user.ID,
			UserName: user.UserName,
		}

		for _, email := range user.Emails {
			if email.Primary {
				secretInfo.UserInfo.PrimaryEmail = email.Value
			}
		}

		return nil
	case http.StatusUnauthorized:
		return fmt.Errorf("invalid/expired personal access token")
	default:
		return fmt.Errorf("unexpected status code: %d for API: %s", statusCode, apiEndpoints[CurrentUser])
	}
}
