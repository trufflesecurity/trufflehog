package baseten

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

const (
	currentUserEndpoint  = "https://api.baseten.co/v1/users/me"
	organizationEndpoint = "https://api.baseten.co/v1/organizations/me"
	apiKeysEndpoint      = "https://api.baseten.co/v1/api_keys"
)

type userResponse struct {
	UserID        string  `json:"user_id"`
	Email         *string `json:"email"`
	Name          string  `json:"name"`
	WorkspaceName string  `json:"workspace_name"`
}

type organizationResponse struct {
	OrgID     string `json:"org_id"`
	Name      string `json:"name"`
	CreatedAt string `json:"created_at"`
}

type apiKeysResponse struct {
	Keys []apiKeyInfo `json:"keys"`
}

type apiKeyInfo struct {
	Prefix     string       `json:"prefix"`
	Name       string       `json:"name"`
	Type       string       `json:"type"`
	ModelIDs   []string     `json:"model_ids"`
	TeamName   string       `json:"team_name"`
	CreatedAt  string       `json:"created_at"`
	LastUsedAt string       `json:"last_used_at"`
	Owner      *apiKeyOwner `json:"owner"`
}

type apiKeyOwner struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Name   string `json:"name"`
}

func makeBasetenRequest(ctx context.Context, client *http.Client, url, key string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+key)

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to send request: %w", err)
	}

	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to read response body: %w", err)
	}

	return body, resp.StatusCode, nil
}

func fetchCurrentUser(ctx context.Context, client *http.Client, key string) (*userResponse, error) {
	body, statusCode, err := makeBasetenRequest(ctx, client, currentUserEndpoint, key)
	if err != nil {
		return nil, err
	}

	switch statusCode {
	case http.StatusOK:
		var user userResponse
		if err := json.Unmarshal(body, &user); err != nil {
			return nil, fmt.Errorf("failed to unmarshal user response: %w", err)
		}
		return &user, nil
	case http.StatusUnauthorized:
		return nil, fmt.Errorf("invalid Baseten API key: status code %d", statusCode)
	default:
		return nil, fmt.Errorf("unexpected status code %d while fetching current user", statusCode)
	}
}

// fetchOrganization returns ok=false, without error, when the key may not
// read its organization.
func fetchOrganization(ctx context.Context, client *http.Client, key string) (*organizationResponse, bool, error) {
	body, statusCode, err := makeBasetenRequest(ctx, client, organizationEndpoint, key)
	if err != nil {
		return nil, false, err
	}

	switch statusCode {
	case http.StatusOK:
		var org organizationResponse
		if err := json.Unmarshal(body, &org); err != nil {
			return nil, false, fmt.Errorf("failed to unmarshal organization response: %w", err)
		}
		return &org, true, nil
	case http.StatusForbidden, http.StatusNotFound:
		return nil, false, nil
	default:
		return nil, false, fmt.Errorf("unexpected status code %d while fetching organization", statusCode)
	}
}

// fetchAPIKeys returns ok=false, without error, when the key may not list API
// keys. Baseten denies listing to service accounts without API key management
// permission, which is the case for team keys.
func fetchAPIKeys(ctx context.Context, client *http.Client, key string) ([]apiKeyInfo, bool, error) {
	body, statusCode, err := makeBasetenRequest(ctx, client, apiKeysEndpoint, key)
	if err != nil {
		return nil, false, err
	}

	switch statusCode {
	case http.StatusOK:
		var keys apiKeysResponse
		if err := json.Unmarshal(body, &keys); err != nil {
			return nil, false, fmt.Errorf("failed to unmarshal api keys response: %w", err)
		}
		return keys.Keys, true, nil
	case http.StatusForbidden:
		return nil, false, nil
	default:
		return nil, false, fmt.Errorf("unexpected status code %d while listing api keys", statusCode)
	}
}
