package groq

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	modelsURL  = "https://api.groq.com/openai/v1/models"
	batchesURL = "https://api.groq.com/openai/v1/batches"
	filesURL   = "https://api.groq.com/openai/v1/files"

	permissionErr       = "permissions_error"
	notAvailableForPlan = "not_available_for_plan"
)

// errorResponse is the body Groq returns when a call is denied.
type errorResponse struct {
	Error struct {
		Message string `json:"message"`
		Type    string `json:"type"`
		Code    string `json:"code"`
	} `json:"error"`
}

// listModelsResponse is the response of GET /openai/v1/models.
type listModelsResponse struct {
	Data []model `json:"data"`
}

// model is a single entry from the models list (free and paid plans).
type model struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	OwnedBy string `json:"owned_by"`
	Created int64  `json:"created"`
}

// listBatchesResponse is the response of GET /openai/v1/batches (paid Developer tier).
type listBatchesResponse struct {
	Data []batch `json:"data"`
}

// batch is a single batch job.
type batch struct {
	ID          string `json:"id"`
	Object      string `json:"object"`
	Endpoint    string `json:"endpoint"`
	InputFileID string `json:"input_file_id"`
	Status      string `json:"status"`
	ExpiresAt   int64  `json:"expires_at"`
}

// listFilesResponse is the response of GET /openai/v1/files (paid Developer tier).
type listFilesResponse struct {
	Data []file `json:"data"`
}

// file is a single uploaded file object.
type file struct {
	ID        string `json:"id"`
	Object    string `json:"object"`
	CreatedAt int64  `json:"created_at"`
	Filename  string `json:"filename"`
	Purpose   string `json:"purpose"`
}

func isPlanRestricted(err errorResponse) bool {
	return err.Error.Type == permissionErr && err.Error.Code == notAvailableForPlan
}

// makeGroqRequest sends an authenticated GET and returns body and status code.
func makeGroqRequest(client *http.Client, url, key string) ([]byte, int, error) {
	req, err := http.NewRequest(http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, 0, err
	}

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

// captureModels lists models via the free-tier endpoint used for detector verification.
// docs: https://console.groq.com/docs/api-reference#models-list
//
// Every valid key can list models, so this is what guarantees analyze bindings
// even when batches/files are plan-restricted or empty.
func captureModels(client *http.Client, key string, secretInfo *SecretInfo) error {
	response, statusCode, err := makeGroqRequest(client, modelsURL, key)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var models listModelsResponse
		if err := json.Unmarshal(response, &models); err != nil {
			return err
		}

		for _, m := range models.Data {
			resource := &GroqResource{
				ID:         m.ID,
				Name:       m.ID,
				Type:       m.Object,
				Permission: PermissionStrings[FullAccess],
			}
			resource.updateMetadata("owned by", m.OwnedBy)
			resource.updateMetadata("created at", time.Unix(m.Created, 0).UTC().Format("2006-01-02 15:04:05 UTC"))
			secretInfo.appendGroqResource(*resource)
		}
		return nil
	case http.StatusUnauthorized:
		secretInfo.Valid = false
		return fmt.Errorf("invalid Groq API key")
	default:
		return fmt.Errorf("unexpected status code: %d", statusCode)
	}
}

// captureBatches lists batch jobs when the account plan includes Batch API.
// docs: https://console.groq.com/docs/api-reference#batches-list
//
// Free-tier keys get not_available_for_plan; treat that as empty, not invalid.
func captureBatches(client *http.Client, key string, secretInfo *SecretInfo) error {
	response, statusCode, err := makeGroqRequest(client, batchesURL, key)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var batches listBatchesResponse
		if err := json.Unmarshal(response, &batches); err != nil {
			return err
		}

		for _, b := range batches.Data {
			resource := &GroqResource{
				ID:         b.ID,
				Name:       b.ID,
				Type:       b.Object,
				Permission: PermissionStrings[FullAccess],
			}
			resource.updateMetadata("status", b.Status)
			resource.updateMetadata("endpoint", b.Endpoint)
			resource.updateMetadata("input file id", b.InputFileID)
			resource.updateMetadata("expires at", time.Unix(b.ExpiresAt, 0).UTC().Format("2006-01-02 15:04:05 UTC"))
			secretInfo.appendGroqResource(*resource)
		}
		return nil
	case http.StatusForbidden:
		var errResp errorResponse
		if err := json.Unmarshal(response, &errResp); err != nil {
			return err
		}
		if isPlanRestricted(errResp) {
			return nil
		}
		return fmt.Errorf("unexpected error: %s", errResp.Error.Message)
	default:
		return fmt.Errorf("unexpected status code: %d", statusCode)
	}
}

// captureFiles lists uploaded files when the account plan includes Files API.
// docs: https://console.groq.com/docs/api-reference#files-list
//
// Free-tier keys get not_available_for_plan; treat that as empty, not invalid.
func captureFiles(client *http.Client, key string, secretInfo *SecretInfo) error {
	response, statusCode, err := makeGroqRequest(client, filesURL, key)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var files listFilesResponse
		if err := json.Unmarshal(response, &files); err != nil {
			return err
		}

		for _, f := range files.Data {
			resource := &GroqResource{
				ID:         f.ID,
				Name:       f.Filename,
				Type:       f.Object,
				Permission: PermissionStrings[FullAccess],
			}
			resource.updateMetadata("purpose", f.Purpose)
			resource.updateMetadata("created at", time.Unix(f.CreatedAt, 0).UTC().Format("2006-01-02 15:04:05 UTC"))
			secretInfo.appendGroqResource(*resource)
		}
		return nil
	case http.StatusForbidden:
		var errResp errorResponse
		if err := json.Unmarshal(response, &errResp); err != nil {
			return err
		}
		if isPlanRestricted(errResp) {
			return nil
		}
		return fmt.Errorf("unexpected error: %s", errResp.Error.Message)
	default:
		return fmt.Errorf("unexpected status code: %d", statusCode)
	}
}
