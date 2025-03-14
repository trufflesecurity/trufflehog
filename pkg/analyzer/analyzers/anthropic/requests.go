package anthropic

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
func makeAnthropicRequest(client *http.Client, url, key string) ([]byte, int, error) {
	// create request
	req, err := http.NewRequest(http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, 0, err
	}

	// add required keys in the header
	req.Header.Set("x-api-key", key)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("anthropic-version", "2023-06-01")

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

// captureAPIKeyResources capture resources associated with api key
func captureAPIKeyResources(client *http.Client, apiKey string, secretInfo *SecretInfo) error {
	if err := captureModels(client, apiKey, secretInfo); err != nil {
		return err
	}

	if err := captureMessageBatches(client, apiKey, secretInfo); err != nil {
		return err
	}

	return nil
}

// captureAdminKeyResources capture resources associated with admin key
func captureAdminKeyResources(client *http.Client, adminKey string, secretInfo *SecretInfo) error {
	if err := captureOrgUsers(client, adminKey, secretInfo); err != nil {
		return err
	}

	if err := captureWorkspaces(client, adminKey, secretInfo); err != nil {
		return err
	}

	if err := captureAPIKeys(client, adminKey, secretInfo); err != nil {
		return err
	}

	return nil
}

func captureModels(client *http.Client, apiKey string, secretInfo *SecretInfo) error {
	response, statusCode, err := makeAnthropicRequest(client, endpoints["models"], apiKey)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var models ModelsResponse

		if err := json.Unmarshal(response, &models); err != nil {
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
		return fmt.Errorf("invalid/revoked api-key")
	default:
		return fmt.Errorf("unexpected status code: %d while fetching models", statusCode)
	}
}

func captureMessageBatches(client *http.Client, apiKey string, secretInfo *SecretInfo) error {
	response, statusCode, err := makeAnthropicRequest(client, endpoints["messageBatches"], apiKey)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var messageBatches MessageResponse

		if err := json.Unmarshal(response, &messageBatches); err != nil {
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
		return fmt.Errorf("invalid/revoked api-key")
	default:
		return fmt.Errorf("unexpected status code: %d while fetching models", statusCode)
	}
}

func captureOrgUsers(client *http.Client, adminKey string, secretInfo *SecretInfo) error {
	response, statusCode, err := makeAnthropicRequest(client, endpoints["orgUsers"], adminKey)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var users OrgUsersResponse

		if err := json.Unmarshal(response, &users); err != nil {
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
		return fmt.Errorf("invalid/revoked api-key")
	default:
		return fmt.Errorf("unexpected status code: %d while fetching models", statusCode)
	}
}

func captureWorkspaces(client *http.Client, adminKey string, secretInfo *SecretInfo) error {
	response, statusCode, err := makeAnthropicRequest(client, endpoints["workspaces"], adminKey)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var workspaces WorkspacesResponse

		if err := json.Unmarshal(response, &workspaces); err != nil {
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
			if err := captureWorkspaceMembers(client, adminKey, resource, secretInfo); err != nil {
				return err
			}
		}

		return nil
	case http.StatusNotFound, http.StatusUnauthorized:
		return fmt.Errorf("invalid/revoked api-key")
	default:
		return fmt.Errorf("unexpected status code: %d while fetching models", statusCode)
	}
}

func captureWorkspaceMembers(client *http.Client, key string, parentWorkspace AnthropicResource, secretInfo *SecretInfo) error {
	response, statusCode, err := makeAnthropicRequest(client, fmt.Sprintf(endpoints["workspaceMembers"], parentWorkspace.ID), key)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var members WorkspaceMembersResponse

		if err := json.Unmarshal(response, &members); err != nil {
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
		return fmt.Errorf("invalid/revoked api-key")
	default:
		return fmt.Errorf("unexpected status code: %d while fetching models", statusCode)
	}
}

func captureAPIKeys(client *http.Client, adminKey string, secretInfo *SecretInfo) error {
	response, statusCode, err := makeAnthropicRequest(client, endpoints["apiKeys"], adminKey)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var apiKeys APIKeysResponse

		if err := json.Unmarshal(response, &apiKeys); err != nil {
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
		return fmt.Errorf("invalid/revoked api-key")
	default:
		return fmt.Errorf("unexpected status code: %d while fetching models", statusCode)
	}
}
