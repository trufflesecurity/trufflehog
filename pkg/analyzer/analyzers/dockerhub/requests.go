package dockerhub

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// LoginResponse is the successful response from the /login API
type LoginResponse struct {
	Token string `json:"token"`
}

// ErrorLoginResponse is the error response from the /login API
type ErrorLoginResponse struct {
	Detail        string `json:"detail"`
	Login2FAToken string `json:"login_2fa_token"` // if login require 2FA authentication
}

// RepositoriesResponse is the /repositories/<namespace> response
type RepositoriesResponse struct {
	Result []struct {
		Name      string `json:"name"`
		Type      string `json:"repository_type"`
		IsPrivate bool   `json:"is_private"`
		StarCount int    `json:"star_count"`
		PullCount int    `json:"pull_count"`
	} `json:"results"`
}

// login call the /login api with username and jwt token and if successful retrieve the token string and return
func login(client *http.Client, username, pat string) (string, error) {
	payload := strings.NewReader(fmt.Sprintf(`{"username": "%s", "password": "%s"}`, username, pat))

	req, err := http.NewRequest(http.MethodPost, "https://hub.docker.com/v2/users/login", payload)
	if err != nil {
		return "", err
	}

	req.Header.Add("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK:
		var token LoginResponse
		if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
			return "", err
		}

		return token.Token, nil
	case http.StatusUnauthorized:
		var errorLogin ErrorLoginResponse
		if err := json.NewDecoder(resp.Body).Decode(&errorLogin); err != nil {
			return "", err
		}

		if errorLogin.Login2FAToken != "" {
			// TODO: handle it more appropriately
			return "", errors.New("valid credentials; account require 2fa authentication")
		}

		return "", errors.New(errorLogin.Detail)
	default:
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}

// fetchRepositories call /repositories/<user_name> API
func fetchRepositories(client *http.Client, username, token string, secretInfo *SecretInfo) error {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://hub.docker.com/v2/repositories/%s", username), http.NoBody)
	if err != nil {
		return err
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK:
		var repositories RepositoriesResponse

		if err := json.NewDecoder(resp.Body).Decode(&repositories); err != nil {
			return err
		}

		// translate repositories response to secretInfo
		repositoriesToSecretInfo(username, &repositories, secretInfo)

		return nil
	case http.StatusUnauthorized, http.StatusForbidden:
		// the token is valid and this shall never happen because the least scope a token can have is repo:public_read.
		return nil
	default:
		return fmt.Errorf("unexpected status code: %d; while fetching repositories information", resp.StatusCode)

	}
}
