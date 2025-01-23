package elevenlabs

import (
	"encoding/json"
	"io"
	"net/http"
	"slices"
)

// permissionToAPIMap contain the API endpoints for each scope/permission
var permissionToAPIMap = map[Permission]string{
	TextToSpeech:                   "https://api.elevenlabs.io/v1/text-to-speech/%s", // require voice id
	SpeechToSpeech:                 "",
	SoundGeneration:                "",
	AudioIsolation:                 "",
	DubbingRead:                    "",
	DubbingWrite:                   "",
	ProjectsRead:                   "",
	ProjectsWrite:                  "",
	AudioNativeRead:                "",
	AudioNativeWrite:               "",
	PronunciationDictionariesRead:  "",
	PronunciationDictionariesWrite: "",
	VoicesRead:                     "",
	VoicesWrite:                    "",
	ModelsRead:                     "",
	SpeechHistoryRead:              "https://api.elevenlabs.io/v1/history",
	SpeechHistoryWrite:             "https://api.elevenlabs.io/v1/history/%s", // require history item id
	UserRead:                       "https://api.elevenlabs.io/v1/user",
	WorkspaceWrite:                 "",
}

var (
	// error statuses
	NotVerifiable = "api_key_not_verifiable"
	InvalidAPIKey = "invalid_api_key"
)

// ErrorResponse is the error response for all APIs
type ErrorResponse struct {
	Detail struct {
		Status string `json:"status"`
	} `json:"detail"`
}

// UserResponse is the /user API response
type UserResponse struct {
	UserID       string `json:"user_id"`
	FirstName    string `json:"first_name"`
	Subscription struct {
		Tier   string `json:"tier"`
		Status string `json:"status"`
	} `json:"subscription"`
}

// HistoryResponse is the /history API response
type HistoryResponse struct {
	History []struct {
		HistoryItemID string `json:"history_item_id"`
		ModelID       string `json:"model_id"`
		VoiceID       string `json:"voice_id"`
	} `json:"history"`
}

// getHistory get history item using the key passed and add them to secret info
func getHistory(client *http.Client, key string, secretInfo *SecretInfo) (*SecretInfo, error) {
	historyResponse, statusCode, err := makeGetRequest(client, permissionToAPIMap[SpeechHistoryRead], key)
	if err != nil {
		return nil, err
	}

	if statusCode == http.StatusOK {
		var history HistoryResponse

		if err := json.Unmarshal(historyResponse, &history); err != nil {
			return nil, err
		}

		// add history read scope to secret info
		secretInfo.Permissions = append(secretInfo.Permissions, PermissionStrings[SpeechHistoryRead])
		// map resource to secret info
		for _, historyItem := range history.History {
			secretInfo.Resources = append(secretInfo.Resources, Resource{
				ID:         historyItem.HistoryItemID,
				Name:       "", // no name
				Type:       "History",
				Permission: PermissionStrings[SpeechHistoryRead],
			})
		}
	}

	return secretInfo, nil
}

// makeGetRequest send the GET request to passed url with passed key as API Key and return response body and status code
func makeGetRequest(client *http.Client, url, key string) ([]byte, int, error) {
	// create request
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, err
	}

	// add key in the header
	req.Header.Add("xi-api-key", key)

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}

	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	/*
		the reason to translate body to byte and does not directly return http.Response
		 is if we return http.Response we cannot close the body in defer. If we do we will get an error
		 when reading body outside this function
	*/
	responseBodyByte, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, err
	}

	return responseBodyByte, resp.StatusCode, nil
}

// checkErrorStatus check if any of expected error status exist in actual API error response
func checkErrorStatus(response []byte, expectedStatuses ...string) (bool, error) {
	var errorResp ErrorResponse

	if err := json.Unmarshal(response, &errorResp); err != nil {
		return false, err
	}

	if slices.Contains(expectedStatuses, errorResp.Detail.Status) {
		return true, nil
	}

	return false, nil
}
