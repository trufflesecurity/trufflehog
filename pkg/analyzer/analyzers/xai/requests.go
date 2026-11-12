package xai

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

const (
	apiKeyEndpoint = "https://api.x.ai/v1/api-key"
	modelsEndpoint = "https://api.x.ai/v1/models"

	aclPrefix   = "api-key:"
	aclEndpoint = "endpoint"
	aclModel    = "model"
	aclWildcard = "*"
)

type apiKeyResponse struct {
	ACLs           []string `json:"acls"`
	APIKeyBlocked  bool     `json:"api_key_blocked"`
	APIKeyDisabled bool     `json:"api_key_disabled"`
	APIKeyID       string   `json:"api_key_id"`
	CreateTime     string   `json:"create_time"`
	ModifiedBy     string   `json:"modified_by"`
	ModifyTime     string   `json:"modify_time"`
	Name           string   `json:"name"`
	RedactedAPIKey string   `json:"redacted_api_key"`
	TeamBlocked    bool     `json:"team_blocked"`
	TeamID         string   `json:"team_id"`
	UserID         string   `json:"user_id"`
}

type modelsResponse struct {
	Data []model `json:"data"`
}

type model struct {
	ID            string   `json:"id"`
	Aliases       []string `json:"aliases"`
	OwnedBy       string   `json:"owned_by"`
	ContextLength *int     `json:"context_length"`
}

func makeXAIRequest(ctx context.Context, client *http.Client, url, key string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")

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

func fetchAPIKeyInfo(ctx context.Context, client *http.Client, key string) (*apiKeyResponse, error) {
	body, statusCode, err := makeXAIRequest(ctx, client, apiKeyEndpoint, key)
	if err != nil {
		return nil, err
	}

	switch statusCode {
	case http.StatusOK:
		var info apiKeyResponse
		if err := json.Unmarshal(body, &info); err != nil {
			return nil, fmt.Errorf("failed to unmarshal api key response: %w", err)
		}
		return &info, nil
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden:
		return nil, fmt.Errorf("invalid xAI API key: status code %d", statusCode)
	default:
		return nil, fmt.Errorf("unexpected status code %d while fetching api key info", statusCode)
	}
}

// fetchModels returns ok=false, without error, when the key's ACLs do not
// permit listing models; callers then fall back to the models named in the ACLs.
func fetchModels(ctx context.Context, client *http.Client, key string) ([]model, bool, error) {
	body, statusCode, err := makeXAIRequest(ctx, client, modelsEndpoint, key)
	if err != nil {
		return nil, false, err
	}

	switch statusCode {
	case http.StatusOK:
		var models modelsResponse
		if err := json.Unmarshal(body, &models); err != nil {
			return nil, false, fmt.Errorf("failed to unmarshal models response: %w", err)
		}
		return models.Data, true, nil
	case http.StatusForbidden, http.StatusNotFound:
		return nil, false, nil
	default:
		return nil, false, fmt.Errorf("unexpected status code %d while fetching models", statusCode)
	}
}

// parseACLs splits ACLs of the form api-key:<kind>:<name> into allowed
// endpoints and models. ACLs in any other form are returned unparsed.
func parseACLs(acls []string) (endpoints, models, unknown []string) {
	for _, acl := range acls {
		kind, name, ok := strings.Cut(strings.TrimPrefix(acl, aclPrefix), ":")
		if !ok || !strings.HasPrefix(acl, aclPrefix) || name == "" {
			unknown = append(unknown, acl)
			continue
		}

		switch kind {
		case aclEndpoint:
			endpoints = append(endpoints, name)
		case aclModel:
			models = append(models, name)
		default:
			unknown = append(unknown, acl)
		}
	}

	return endpoints, models, unknown
}
