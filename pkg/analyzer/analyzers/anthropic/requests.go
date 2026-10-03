package anthropic

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

var endpoints = map[string]string{
	// api key endpoints
	"models":         "https://api.anthropic.com/v1/models",
	"messageBatches": "https://api.anthropic.com/v1/messages/batches",

	// admin key endpoints
	"orgUsers":         "https://api.anthropic.com/v1/organizations/users",
	"workspaces":       "https://api.anthropic.com/v1/organizations/workspaces",
	"workspaceMembers": "https://api.anthropic.com/v1/organizations/workspaces/%s/members", // require workspace id
	"apiKeys":          "https://api.anthropic.com/v1/organizations/api_keys",
}

type ModelsResponse struct {
	Data []struct {
		ID          string `json:"id"`
		DisplayName string `json:"display_name"`
		Type        string `json:"type"`
	} `json:"data"`
}

type MessageResponse struct {
	Data []struct {
		ID               string `json:"id"`
		Type             string `json:"type"`
		ProcessingStatus string `json:"processing_status"`
		ExpiresAt        string `json:"expires_at"`
		ResultsURL       string `json:"results_url"`
	} `json:"data"`
}

type OrgUsersResponse struct {
	Data []struct {
		ID    string `json:"id"`
		Type  string `json:"type"`
		Email string `json:"email"`
		Name  string `json:"name"`
		Role  string `json:"role"`
	} `json:"data"`
}

type WorkspacesResponse struct {
	Data []struct {
		ID   string `json:"id"`
		Type string `json:"type"`
		Name string `json:"name"`
	} `json:"data"`
}

type WorkspaceMembersResponse struct {
	Data []struct {
		WorkspaceID   string `json:"workspace_id"`
		UserID        string `json:"user_id"`
		Type          string `json:"type"`
		WorkspaceRole string `json:"workspace_role"`
	} `json:"data"`
}

type APIKeysResponse struct {
	Data []struct {
		ID          string `json:"id"`
		Type        string `json:"type"`
		Name        string `json:"name"`
		WorkspaceID string `json:"workspace_id"`
		CreatedBy   struct {
			ID string `json:"id"`
		} `json:"created_by"`
		PartialKeyHint string `json:"partial_key_hint"`
		Status         string `json:"status"`
	} `json:"data"`
}

// makeAnthropicRequest send the API request to passed url with passed key as API Key and return response body and status code
func makeAnthropicRequest(ctx context.Context, client *http.Client, url, key string) ([]byte, int, error) {
	// create request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		ctx.Logger().Error(err, "failed to create anthropic request", "url", url)
		return nil, 0, err
	}

	// add required keys in the header
	req.Header.Set("x-api-key", key)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := client.Do(req)
	if err != nil {
		ctx.Logger().Error(err, "failed to send anthropic request", "url", url)
		return nil, 0, err
	}

	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	responseBodyByte, err := io.ReadAll(resp.Body)
	if err != nil {
		ctx.Logger().Error(err, "failed to read anthropic response body", "url", url)
		return nil, 0, err
	}

	return responseBodyByte, resp.StatusCode, nil
}

// captureAPIKeyResources capture resources associated with api key
func captureAPIKeyResources(ctx context.Context, client *http.Client, apiKey string, secretInfo *SecretInfo) error {
	if err := captureModels(ctx, client, apiKey, secretInfo); err != nil {
		return err
	}

	if err := captureMessageBatches(ctx, client, apiKey, secretInfo); err != nil {
		return err
	}

	return nil
}

// captureAdminKeyResources capture resources associated with admin key
func captureAdminKeyResources(ctx context.Context, client *http.Client, adminKey string, secretInfo *SecretInfo) error {
	if err := captureOrgUsers(ctx, client, adminKey, secretInfo); err != nil {
		return err
	}

	if err := captureWorkspaces(ctx, client, adminKey, secretInfo); err != nil {
		return err
	}

	if err := captureAPIKeys(ctx, client, adminKey, secretInfo); err != nil {
		return err
	}

	return nil
}

func captureModels(ctx context.Context, client *http.Client, apiKey string, secretInfo *SecretInfo) error {
	response, statusCode, err := makeAnthropicRequest(ctx, client, endpoints["models"], apiKey)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var models ModelsResponse

		if err := json.Unmarshal(response, &models); err != nil {
			ctx.Logger().Error(err, "failed to unmarshal models response")
			return err
		}

		for _, model := range models.Data {
			secretInfo.AnthropicResources = append(secretInfo.AnthropicResources, AnthropicResource{
				ID:   model.ID,
				Name: model.DisplayName,
				Type: model.Type,
			})
		}

		return nil
	case http.StatusNotFound, http.StatusUnauthorized:
		err := fmt.Errorf("invalid/revoked api-key")
		ctx.Logger().Error(err, "anthropic key invalid while fetching models", "status_code", statusCode)
		return err
	default:
		err := fmt.Errorf("unexpected status code: %d while fetching models", statusCode)
		ctx.Logger().Error(err, "unexpected status code while fetching models", "status_code", statusCode)
		return err
	}
}

func captureMessageBatches(ctx context.Context, client *http.Client, apiKey string, secretInfo *SecretInfo) error {
	response, statusCode, err := makeAnthropicRequest(ctx, client, endpoints["messageBatches"], apiKey)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var messageBatches MessageResponse

		if err := json.Unmarshal(response, &messageBatches); err != nil {
			ctx.Logger().Error(err, "failed to unmarshal message batches response")
			return err
		}

		for _, messageBatch := range messageBatches.Data {
			secretInfo.AnthropicResources = append(secretInfo.AnthropicResources, AnthropicResource{
				ID:   messageBatch.ID,
				Name: "", // no name
				Type: messageBatch.Type,
				Metadata: map[string]string{
					"expires_at":  messageBatch.ExpiresAt,
					"results_url": messageBatch.ResultsURL,
				},
			})
		}

		return nil
	case http.StatusNotFound, http.StatusUnauthorized:
		err := fmt.Errorf("invalid/revoked api-key")
		ctx.Logger().Error(err, "anthropic key invalid while fetching message batches", "status_code", statusCode)
		return err
	default:
		err := fmt.Errorf("unexpected status code: %d while fetching message batches", statusCode)
		ctx.Logger().Error(err, "unexpected status code while fetching message batches", "status_code", statusCode)
		return err
	}
}

func captureOrgUsers(ctx context.Context, client *http.Client, adminKey string, secretInfo *SecretInfo) error {
	response, statusCode, err := makeAnthropicRequest(ctx, client, endpoints["orgUsers"], adminKey)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var users OrgUsersResponse

		if err := json.Unmarshal(response, &users); err != nil {
			ctx.Logger().Error(err, "failed to unmarshal org users response")
			return err
		}

		for _, user := range users.Data {
			secretInfo.AnthropicResources = append(secretInfo.AnthropicResources, AnthropicResource{
				ID:   user.ID,
				Name: user.Name,
				Type: user.Type,
				Metadata: map[string]string{
					"Role":  user.Role,
					"Email": user.Email,
				},
			})
		}

		return nil
	case http.StatusNotFound, http.StatusUnauthorized:
		err := fmt.Errorf("invalid/revoked api-key")
		ctx.Logger().Error(err, "anthropic key invalid while fetching org users", "status_code", statusCode)
		return err
	default:
		err := fmt.Errorf("unexpected status code: %d while fetching org users", statusCode)
		ctx.Logger().Error(err, "unexpected status code while fetching org users", "status_code", statusCode)
		return err
	}
}

func captureWorkspaces(ctx context.Context, client *http.Client, adminKey string, secretInfo *SecretInfo) error {
	response, statusCode, err := makeAnthropicRequest(ctx, client, endpoints["workspaces"], adminKey)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var workspaces WorkspacesResponse

		if err := json.Unmarshal(response, &workspaces); err != nil {
			ctx.Logger().Error(err, "failed to unmarshal workspaces response")
			return err
		}

		for _, workspace := range workspaces.Data {
			resource := AnthropicResource{
				ID:   workspace.ID,
				Name: workspace.Name,
				Type: workspace.Type,
			}

			secretInfo.AnthropicResources = append(secretInfo.AnthropicResources, resource)
			// capture each workspace members
			if err := captureWorkspaceMembers(ctx, client, adminKey, resource, secretInfo); err != nil {
				return err
			}
		}

		return nil
	case http.StatusNotFound, http.StatusUnauthorized:
		err := fmt.Errorf("invalid/revoked api-key")
		ctx.Logger().Error(err, "anthropic key invalid while fetching workspaces", "status_code", statusCode)
		return err
	default:
		err := fmt.Errorf("unexpected status code: %d while fetching workspaces", statusCode)
		ctx.Logger().Error(err, "unexpected status code while fetching workspaces", "status_code", statusCode)
		return err
	}
}

func captureWorkspaceMembers(ctx context.Context, client *http.Client, key string, parentWorkspace AnthropicResource, secretInfo *SecretInfo) error {
	response, statusCode, err := makeAnthropicRequest(ctx, client, fmt.Sprintf(endpoints["workspaceMembers"], parentWorkspace.ID), key)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var members WorkspaceMembersResponse

		if err := json.Unmarshal(response, &members); err != nil {
			ctx.Logger().Error(err, "failed to unmarshal workspace members response", "workspace_id", parentWorkspace.ID)
			return err
		}

		for _, member := range members.Data {
			secretInfo.AnthropicResources = append(secretInfo.AnthropicResources, AnthropicResource{
				ID:     fmt.Sprintf("anthropic/workspace/%s/member/%s", member.WorkspaceID, member.UserID),
				Name:   member.UserID,
				Type:   member.Type,
				Parent: &parentWorkspace,
			})
		}

		return nil
	case http.StatusNotFound, http.StatusUnauthorized:
		err := fmt.Errorf("invalid/revoked api-key")
		ctx.Logger().Error(err, "anthropic key invalid while fetching workspace members", "workspace_id", parentWorkspace.ID, "status_code", statusCode)
		return err
	default:
		err := fmt.Errorf("unexpected status code: %d while fetching workspace members", statusCode)
		ctx.Logger().Error(err, "unexpected status code while fetching workspace members", "workspace_id", parentWorkspace.ID, "status_code", statusCode)
		return err
	}
}

func captureAPIKeys(ctx context.Context, client *http.Client, adminKey string, secretInfo *SecretInfo) error {
	response, statusCode, err := makeAnthropicRequest(ctx, client, endpoints["apiKeys"], adminKey)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var apiKeys APIKeysResponse

		if err := json.Unmarshal(response, &apiKeys); err != nil {
			ctx.Logger().Error(err, "failed to unmarshal api keys response")
			return err
		}

		for _, apiKey := range apiKeys.Data {
			secretInfo.AnthropicResources = append(secretInfo.AnthropicResources, AnthropicResource{
				ID:   apiKey.ID,
				Name: apiKey.Name,
				Type: apiKey.Type,
				Metadata: map[string]string{
					"WorkspaceID":    apiKey.WorkspaceID,
					"CreatedBy":      apiKey.CreatedBy.ID,
					"PartialKeyHint": apiKey.PartialKeyHint,
					"Status":         apiKey.Status,
				},
			})
		}

		return nil
	case http.StatusNotFound, http.StatusUnauthorized:
		err := fmt.Errorf("invalid/revoked api-key")
		ctx.Logger().Error(err, "anthropic key invalid while fetching api keys", "status_code", statusCode)
		return err
	default:
		err := fmt.Errorf("unexpected status code: %d while fetching api keys", statusCode)
		ctx.Logger().Error(err, "unexpected status code while fetching api keys", "status_code", statusCode)
		return err
	}
}
