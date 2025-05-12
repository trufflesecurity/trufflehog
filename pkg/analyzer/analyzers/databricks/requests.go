package databricks

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

var (
	apiEndpoints = map[ResourceType]string{
		CurrentUser: "/api/2.0/preview/scim/v2/Me",
		TokensInfo:  "/api/2.0/token-management/tokens",
	}
)

// makeDataBricksRequest send the API request to passed url with passed key as access token and return response body and status code
func makeDataBricksRequest(client *http.Client, endpoint, token string) ([]byte, int, error) {
	// create request
	req, err := http.NewRequest(http.MethodGet, "https://"+endpoint, http.NoBody)
	if err != nil {
		return nil, 0, err
	}

	// add key in the header
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))

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

func captureUserInfo(client *http.Client, domain, token string, secretInfo *SecretInfo) error {
	respBody, statusCode, err := makeDataBricksRequest(client, domain+apiEndpoints[CurrentUser], token)
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

func captureTokensInfo(client *http.Client, domain, token string, secretInfo *SecretInfo) error {
	respBody, statusCode, err := makeDataBricksRequest(client, domain+apiEndpoints[TokensInfo], token)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var tokens Tokens

		if err := json.Unmarshal(respBody, &tokens); err != nil {
			return err
		}

		for _, token := range tokens.TokensInfo {
			t := Token{
				ID:          token.ID,
				Name:        token.Name,
				ExpiryTime:  readableTime(token.ExpiryTime),
				LastUsedDay: readableTime(token.LastUsedDay),
				CreatedBy:   token.CreatedBy,
			}

			secretInfo.Tokens = append(secretInfo.Tokens, t)
		}

		return nil
	case http.StatusUnauthorized:
		return fmt.Errorf("invalid/expired personal access token")
	default:
		return fmt.Errorf("unexpected status code: %d for API: %s", statusCode, apiEndpoints[CurrentUser])
	}
}

func readableTime(timestamp int) string {
	timestampMillis := int64(timestamp)
	t := time.Unix(timestampMillis/1000, (timestampMillis%1000)*int64(time.Millisecond))

	return t.Format("2006-01-02 15:04:05")
}
