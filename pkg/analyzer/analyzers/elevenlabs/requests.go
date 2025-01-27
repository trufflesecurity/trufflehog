package elevenlabs

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
)

// permissionToAPIMap contain the API endpoints for each scope/permission
// api docs: https://elevenlabs.io/docs/api-reference/introduction
var permissionToAPIMap = map[Permission]string{
	TextToSpeech:                   "https://api.elevenlabs.io/v1/text-to-speech/%s", // require voice id
	SpeechToSpeech:                 "",
	SoundGeneration:                "",
	AudioIsolation:                 "",
	DubbingRead:                    "https://api.elevenlabs.io/v1/dubbing/%s", // require dubbing id
	DubbingWrite:                   "https://api.elevenlabs.io/v1/dubbing/%s", // require dubbing id
	ProjectsRead:                   "https://api.elevenlabs.io/v1/projects",
	ProjectsWrite:                  "https://api.elevenlabs.io/v1/projects/%s", // require project id
	AudioNativeRead:                "",
	AudioNativeWrite:               "",
	PronunciationDictionariesRead:  "",
	PronunciationDictionariesWrite: "",
	VoicesRead:                     "https://api.elevenlabs.io/v1/voices",
	VoicesWrite:                    "https://api.elevenlabs.io/v1/voices/%s", // require voice id
	ModelsRead:                     "",
	SpeechHistoryRead:              "https://api.elevenlabs.io/v1/history",
	SpeechHistoryWrite:             "https://api.elevenlabs.io/v1/history/%s", // require history item id
	UserRead:                       "https://api.elevenlabs.io/v1/user",
	WorkspaceWrite:                 "",
}

var (
	// not exist key
	fakeID = "_thou_shalt_not_exist_"
	// error statuses
	NotVerifiable       = "api_key_not_verifiable"
	InvalidAPIKey       = "invalid_api_key"
	MissingPermissions  = "missing_permissions"
	DubbingNotFound     = "dubbing_not_found"
	ProjectNotFound     = "project_not_found"
	VoiceNotFound       = "voice_does_not_exist"
	InvalidSubscription = "invalid_subscription"
	InternalServerError = "internal_server_error"
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
		ID      string `json:"history_item_id"`
		ModelID string `json:"model_id"`
		VoiceID string `json:"voice_id"`
	} `json:"history"`
}

type VoicesResponse struct {
	Voices []struct {
		ID       string `json:"voice_id"`
		Name     string `json:"name"`
		Category string `json:"category"`
	} `json:"voices"`
}

type ProjectsResponse struct {
	Projects []struct {
		ID          string `json:"project_id"`
		Name        string `json:"name"`
		State       string `json:"state"`
		AccessLevel string `json:"access_level"`
	} `json:"projects"`
}

// getAPIUrl return the API Url mapped to the permission
func getAPIUrl(permission Permission) string {
	apiUrl := permissionToAPIMap[permission]
	if strings.Contains(apiUrl, "%s") {
		return fmt.Sprintf(apiUrl, fakeID)
	}

	return apiUrl
}

// makeElevenLabsRequest send the API request to passed url with passed key as API Key and return response body and status code
func makeElevenLabsRequest(client *http.Client, url, method, key string) ([]byte, int, error) {
	// create request
	req, err := http.NewRequest(method, url, nil)
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

// getHistory get history item using the key passed and add them to secret info
func getHistory(client *http.Client, key string, secretInfo *SecretInfo) error {
	response, statusCode, err := makeElevenLabsRequest(client, getAPIUrl(SpeechHistoryRead), http.MethodGet, key)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var history HistoryResponse

		if err := json.Unmarshal(response, &history); err != nil {
			return err
		}

		// add history read scope to secret info
		secretInfo.Permissions = append(secretInfo.Permissions, PermissionStrings[SpeechHistoryRead])
		// map resource to secret info
		for _, historyItem := range history.History {
			secretInfo.Resources = append(secretInfo.Resources, Resource{
				ID:         historyItem.ID,
				Name:       "", // no name
				Type:       "History",
				Permission: PermissionStrings[SpeechHistoryRead],
			})
		}

		return nil
	case http.StatusUnauthorized:
		return handleErrorStatus(response, "", secretInfo, MissingPermissions)
	default:
		return fmt.Errorf("unexpected status code: %d while checking history read scope", statusCode)
	}
}

// deleteHistory try to delete a history item. The item must not exist.
func deleteHistory(client *http.Client, key string, secretInfo *SecretInfo) error {
	response, statusCode, err := makeElevenLabsRequest(client, getAPIUrl(SpeechHistoryWrite), http.MethodDelete, key)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusInternalServerError:
		// for some reason if we send fake id and token has the permission, the history api return 500 error instead of 404
		// issue opened in elevenlabs-docs: https://github.com/elevenlabs/elevenlabs-docs/issues/649
		return handleErrorStatus(response, PermissionStrings[SpeechHistoryWrite], secretInfo, InternalServerError)
	case http.StatusUnauthorized:
		return handleErrorStatus(response, "", secretInfo, MissingPermissions)
	default:
		return fmt.Errorf("unexpected status code: %d while checking history write scope", statusCode)
	}
}

// deleteDubbing try to delete a dubbing. The item must not exist.
func deleteDubbing(client *http.Client, key string, secretInfo *SecretInfo) error {
	response, statusCode, err := makeElevenLabsRequest(client, getAPIUrl(DubbingWrite), http.MethodDelete, key)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusNotFound:
		// as we send fake id, if permission is assigned to token we must get 404 dubbing not found
		if err := handleErrorStatus(response, PermissionStrings[DubbingWrite], secretInfo, DubbingNotFound); err != nil {
			return err
		}

		// add read scope of dubbing to avoid get dubbing api call
		secretInfo.Permissions = append(secretInfo.Permissions, PermissionStrings[DubbingRead])

		return nil
	case http.StatusUnauthorized:
		return handleErrorStatus(response, "", secretInfo, MissingPermissions)
	default:
		return fmt.Errorf("unexpected status code: %d while checking dubbing write scope", statusCode)
	}
}

// getDebugging try to get a dubbing. The item must not exist.
func getDebugging(client *http.Client, key string, secretInfo *SecretInfo) error {
	response, statusCode, err := makeElevenLabsRequest(client, getAPIUrl(DubbingRead), http.MethodGet, key)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusNotFound:
		// as we send fake id, if permission is assigned to token we must get 404 dubbing not found
		return handleErrorStatus(response, PermissionStrings[DubbingRead], secretInfo, DubbingNotFound)
	case http.StatusUnauthorized:
		return handleErrorStatus(response, "", secretInfo, MissingPermissions)
	default:
		return fmt.Errorf("unexpected status code: %d while checking dubbing read scope", statusCode)
	}
}

// getVoices get list of voices using the key passed and add them to secret info
func getVoices(client *http.Client, key string, secretInfo *SecretInfo) error {
	response, statusCode, err := makeElevenLabsRequest(client, getAPIUrl(VoicesRead), http.MethodGet, key)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var voices VoicesResponse

		if err := json.Unmarshal(response, &voices); err != nil {
			return err
		}

		// add voices read scope to secret info
		secretInfo.Permissions = append(secretInfo.Permissions, PermissionStrings[VoicesRead])
		// map resource to secret info
		for _, voice := range voices.Voices {
			secretInfo.Resources = append(secretInfo.Resources, Resource{
				ID:         voice.ID,
				Name:       voice.Name,
				Type:       "Voice",
				Permission: PermissionStrings[VoicesRead],
				Metadata: map[string]string{
					"category": voice.Category,
				},
			})
		}

		return nil
	case http.StatusUnauthorized:
		return handleErrorStatus(response, "", secretInfo, MissingPermissions)
	default:
		return fmt.Errorf("unexpected status code: %d while checking voice read scope", statusCode)
	}
}

// deleteVoice try to delete a voice. The item must not exist.
func deleteVoice(client *http.Client, key string, secretInfo *SecretInfo) error {
	response, statusCode, err := makeElevenLabsRequest(client, getAPIUrl(VoicesWrite), http.MethodDelete, key)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusBadRequest:
		// if permission was assigned to scope we should get 400 error with voice not found status
		return handleErrorStatus(response, PermissionStrings[VoicesWrite], secretInfo, VoiceNotFound)
	case http.StatusUnauthorized:
		return handleErrorStatus(response, "", secretInfo, MissingPermissions)
	default:
		return fmt.Errorf("unexpected status code: %d while checking voice write scope", statusCode)
	}
}

// getProjects get list of projects using the key passed and add them to secret info
func getProjects(client *http.Client, key string, secretInfo *SecretInfo) error {
	response, statusCode, err := makeElevenLabsRequest(client, getAPIUrl(ProjectsRead), http.MethodGet, key)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var projects ProjectsResponse

		if err := json.Unmarshal(response, &projects); err != nil {
			return err
		}

		// add project read scope to secret info
		secretInfo.Permissions = append(secretInfo.Permissions, PermissionStrings[ProjectsRead])
		// map resource to secret info
		for _, project := range projects.Projects {
			secretInfo.Resources = append(secretInfo.Resources, Resource{
				ID:         project.ID,
				Name:       project.Name,
				Type:       "Project",
				Permission: PermissionStrings[ProjectsRead],
				Metadata: map[string]string{
					"state":        project.State,
					"access level": project.AccessLevel, // access level of project
				},
			})
		}

		return nil
	case http.StatusForbidden:
		// if token has the permission but trail is free, projects are not accessable
		return handleErrorStatus(response, PermissionStrings[ProjectsRead], secretInfo, InvalidSubscription)
	case http.StatusUnauthorized:
		return handleErrorStatus(response, "", secretInfo, MissingPermissions)
	default:
		return fmt.Errorf("unexpected status code: %d while checking projects read scope", statusCode)
	}
}

// deleteProject try to delete a project. The item must not exist.
func deleteProject(client *http.Client, key string, secretInfo *SecretInfo) error {
	response, statusCode, err := makeElevenLabsRequest(client, getAPIUrl(ProjectsWrite), http.MethodDelete, key)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusBadRequest:
		// if permission was assigned to token we should get 400 error with project not found status
		return handleErrorStatus(response, PermissionStrings[ProjectsWrite], secretInfo, ProjectNotFound)
	case http.StatusForbidden:
		// if token has the permission but trail is free, projects are not accessable
		return handleErrorStatus(response, PermissionStrings[ProjectsWrite], secretInfo, InvalidSubscription)
	case http.StatusUnauthorized:
		return handleErrorStatus(response, "", secretInfo, MissingPermissions)
	default:
		return fmt.Errorf("unexpected status code: %d while checking project write scope", statusCode)
	}
}

// handleErrorStatus handle error response, check if expected error status is in the response and add require permission to secret info
// this is used in case where we expect error respones with specific status mostly in write calls
func handleErrorStatus(response []byte, permissionToAdd string, secretInfo *SecretInfo, expectedErrStatuses ...string) error {
	// check if status in response is what is expected to be
	ok, err := checkErrorStatus(response, expectedErrStatuses...)
	if err != nil {
		return err
	}

	// if permission to add was passed and it was expected error status add the permission
	if permissionToAdd != "" && ok {
		secretInfo.Permissions = append(secretInfo.Permissions, permissionToAdd)
	}

	return nil
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
