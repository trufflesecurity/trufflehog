package groq

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

var (
	permissionErr       = "permissions_error"
	notAvailableForPlan = "not_available_for_plan"
)

// errorResponse is the response from groq APIs in case of any error
type errorResponse struct {
	Error struct {
		Message string `json:"message"`
		Type    string `json:"type"`
		Code    string `json:"code"`
	} `json:"error"`
}

// listBatchesResponse is the response of /v1/batches API
type listBatchesResponse struct {
	Data []batch `json:"data"`
}

// batch represent a single batch inside batches list
type batch struct {
	ID          string `json:"id"`
	Object      string `json:"object"`
	Endpoint    string `json:"endpoint"`
	InputFileID string `json:"input_file_id"`
	Status      string `json:"status"`
	ExpiresAt   int64  `json:"expires_at"`
}

// listBatchesResponse is the response of /v1/files API
type listFilesResponse struct {
	Data []file `json:"data"`
}

// file represents a single file object inside files list
type file struct {
	ID        string `json:"id"`
	Object    string `json:"object"`
	CreatedAt int64  `json:"created_at"`
	Filename  string `json:"filename"`
	Purpose   string `json:"purpose"`
}

func isPermissionError(err errorResponse) bool {
	// has permissions error or not available for the plan subscribed
	if err.Error.Type == permissionErr && err.Error.Code == notAvailableForPlan {
		return true
	}

	return false
}

// makeGroqRequest send the API request to passed url with passed key as API Key and return response body and status code
func makeGroqRequest(client *http.Client, url, key string) ([]byte, int, error) {
	// create request
	req, err := http.NewRequest(http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, 0, err
	}

	// add required keys in the header
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")

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

// docs: https://console.groq.com/docs/api-reference#batches-list
func captureBatches(client *http.Client, key string, secretInfo *SecretInfo) error {
	response, statusCode, err := makeGroqRequest(client, "https://api.groq.com/openai/v1/batches", key)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var batches listBatchesResponse

		if err := json.Unmarshal(response, &batches); err != nil {
			return err
		}

		for _, batch := range batches.Data {
			resource := GroqResource{
				ID:         batch.ID,
				Name:       batch.ID, // no specific name for batch
				Type:       batch.Object,
				Permission: PermissionStrings[FullAccess],
			}

			resource.updateMetadata("status", batch.Status)
			resource.updateMetadata("endpoint", batch.Endpoint)
			resource.updateMetadata("input file id", batch.InputFileID)
			resource.updateMetadata("expires at", time.Unix(batch.ExpiresAt, 0).UTC().Format("2006-01-02 15:04:05 UTC"))

			secretInfo.appendGroqResource(resource)
		}

		return nil
	case http.StatusForbidden:
		var errResp errorResponse

		if err := json.Unmarshal(response, &errResp); err != nil {
			return err
		}

		if isPermissionError(errResp) {
			return nil
		}

		return fmt.Errorf("unexpected error: %s", errResp.Error.Message)
	default:
		return fmt.Errorf("unexpected status code: %d", statusCode)
	}
}

// docs: https://console.groq.com/docs/api-reference#files-list
func captureFiles(client *http.Client, key string, secretInfo *SecretInfo) error {
	response, statusCode, err := makeGroqRequest(client, "https://api.groq.com/openai/v1/files", key)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var files listFilesResponse

		if err := json.Unmarshal(response, &files); err != nil {
			return err
		}

		for _, file := range files.Data {
			resource := GroqResource{
				ID:         file.ID,
				Name:       file.Filename,
				Type:       file.Object,
				Permission: PermissionStrings[FullAccess],
			}

			resource.updateMetadata("purpose", file.Purpose)
			resource.updateMetadata("created at", time.Unix(file.CreatedAt, 0).UTC().Format("2006-01-02 15:04:05 UTC"))

			secretInfo.appendGroqResource(resource)
		}

		return nil
	case http.StatusForbidden:
		var errResp errorResponse

		if err := json.Unmarshal(response, &errResp); err != nil {
			return err
		}

		if isPermissionError(errResp) {
			return nil
		}

		return fmt.Errorf("unexpected error: %s", errResp.Error.Message)
	default:
		return fmt.Errorf("unexpected status code: %d", statusCode)
	}
}
