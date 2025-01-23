package elevenlabs

import (
	"encoding/json"
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
	SpeechHistoryRead:              "",
	SpeechHistoryWrite:             "",
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
