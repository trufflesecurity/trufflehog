package anthropic

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

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

func listModels(client *http.Client, key string, secretInfo *SecretInfo) error {
	response, statusCode, err := makeAnthropicRequest(client, "https://api.anthropic.com/v1/models", key)
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

func listMessageBatches(client *http.Client, key string, secretInfo *SecretInfo) error {
	response, statusCode, err := makeAnthropicRequest(client, "https://api.anthropic.com/v1/messages/batches", key)
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
