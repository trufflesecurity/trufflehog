package elevenlabs

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"slices"
	"strings"
)

// permissionToAPIMap contain the API endpoints for each scope/permission
// api docs: https://elevenlabs.io/docs/api-reference/introduction
var permissionToAPIMap = map[Permission]string{
	TextToSpeech:                   "https://api.elevenlabs.io/v1/text-to-speech/%s",   // require voice id
	SpeechToSpeech:                 "https://api.elevenlabs.io/v1/speech-to-speech/%s", // require voice id
	AudioIsolation:                 "https://api.elevenlabs.io/v1/audio-isolation",
	DubbingRead:                    "https://api.elevenlabs.io/v1/dubbing/%s", // require dubbing id
	DubbingWrite:                   "https://api.elevenlabs.io/v1/dubbing/%s", // require dubbing id
	ProjectsRead:                   "https://api.elevenlabs.io/v1/projects",
	ProjectsWrite:                  "https://api.elevenlabs.io/v1/projects/%s",             // require project id
	AudioNativeWrite:               "https://api.elevenlabs.io/v1/audio-native/%s/content", // require project id
	PronunciationDictionariesRead:  "https://api.elevenlabs.io/v1/pronunciation-dictionaries",
	PronunciationDictionariesWrite: "https://api.elevenlabs.io/v1/pronunciation-dictionaries/%s/remove-rules", // require pronunciation dictionary id
	VoicesRead:                     "https://api.elevenlabs.io/v1/voices",
	VoicesWrite:                    "https://api.elevenlabs.io/v1/voices/%s", // require voice id
	ModelsRead:                     "https://api.elevenlabs.io/v1/models",
	SpeechHistoryRead:              "https://api.elevenlabs.io/v1/history",
	SpeechHistoryWrite:             "https://api.elevenlabs.io/v1/history/%s", // require history item id
	UserRead:                       "https://api.elevenlabs.io/v1/user",
	WorkspaceWrite:                 "https://api.elevenlabs.io/v1/workspace/invites",
}

var (
	// not exist key
	fakeID = "_thou_shalt_not_exist_"
	// error statuses
	NotVerifiable                   = "api_key_not_verifiable"
	InvalidAPIKey                   = "invalid_api_key"
	MissingPermissions              = "missing_permissions"
	DubbingNotFound                 = "dubbing_not_found"
	ProjectNotFound                 = "project_not_found"
	VoiceDoesNotExist               = "voice_does_not_exist"
	InvalidSubscription             = "invalid_subscription"
	PronunciationDictionaryNotFound = "pronunciation_dictionary_not_found"
	InternalServerError             = "internal_server_error"
	InvalidProjectID                = "invalid_project_id"
	ModelNotFound                   = "model_not_found"
	VoiceNotFound                   = "voice_not_found"
	InvalidContent                  = "invalid_content"
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

// VoiceResponse is the /voices API response
type VoicesResponse struct {
	Voices []struct {
		ID       string `json:"voice_id"`
		Name     string `json:"name"`
		Category string `json:"category"`
	} `json:"voices"`
}

// ProjectsResponse is the /projects API response
type ProjectsResponse struct {
	Projects []struct {
		ID          string `json:"project_id"`
		Name        string `json:"name"`
		State       string `json:"state"`
		AccessLevel string `json:"access_level"`
	} `json:"projects"`
}

// PronunciationDictionaries is the /pronunciation-dictionaries API response
type PronunciationDictionariesResponse struct {
	PronunciationDictionaries []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"pronunciation_dictionaries"`
}

// Models is the /models API response
type ModelsResponse struct {
	ID   string `json:"model_id"`
	Name string `json:"name"`
}

// AgentsResponse is the /agents API response
type AgentsResponse struct {
	Agents []struct {
		ID          string `json:"agent_id"`
		Name        string `json:"name"`
		AccessLevel string `json:"access_level"`
	} `json:"agents"`
}

// ConversationResponse is the /conversation API response
type ConversationResponse struct {
	Conversations []struct {
		AgentID string `json:"agent_id"`
		ID      string `json:"conversation_id"`
		Status  string `json:"status"`
	}
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
	req, err := http.NewRequest(method, url, http.NoBody)
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

// makeElevenLabsRequestWithPayload sends a POST/PATCH API request to the passed URL with the given key as the API Key
// and an optional payload. It returns the response body and status code.
func makeElevenLabsRequestWithPayload(client *http.Client, url, method, contentType, key string, payload []byte) ([]byte, int, error) {
	// Create request with payload
	req, err := http.NewRequest(method, url, bytes.NewBuffer(payload))
	if err != nil {
		return nil, 0, err
	}

	// Add headers
	req.Header.Add("xi-api-key", key)
	req.Header.Add("Content-Type", contentType)

	// Send the request
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}

	// ensure the response body is properly closed
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	// read the response body
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
		secretInfo.AppendPermission(PermissionStrings[SpeechHistoryRead])
		// map resource to secret info
		for _, historyItem := range history.History {
			secretInfo.AppendResource(ElevenLabsResource{
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
		secretInfo.AppendPermission(PermissionStrings[DubbingRead])

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
		secretInfo.AppendPermission(PermissionStrings[VoicesRead])
		// map resource to secret info
		for _, voice := range voices.Voices {
			secretInfo.AppendResource(ElevenLabsResource{
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
		return handleErrorStatus(response, PermissionStrings[VoicesWrite], secretInfo, VoiceDoesNotExist)
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
		secretInfo.AppendPermission(PermissionStrings[ProjectsRead])
		// map resource to secret info
		for _, project := range projects.Projects {
			secretInfo.AppendResource(ElevenLabsResource{
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
		// if token has the permission but trail is free, projects are not accessible
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
		// if token has the permission but trail is free, projects are not accessible
		return handleErrorStatus(response, PermissionStrings[ProjectsWrite], secretInfo, InvalidSubscription)
	case http.StatusUnauthorized:
		return handleErrorStatus(response, "", secretInfo, MissingPermissions)
	default:
		return fmt.Errorf("unexpected status code: %d while checking project write scope", statusCode)
	}
}

// getPronunciationDictionaries get list of pronunciation dictionaries using the key passed and add them to secret info
func getPronunciationDictionaries(client *http.Client, key string, secretInfo *SecretInfo) error {
	response, statusCode, err := makeElevenLabsRequest(client, getAPIUrl(PronunciationDictionariesRead), http.MethodGet, key)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var PDs PronunciationDictionariesResponse

		if err := json.Unmarshal(response, &PDs); err != nil {
			return err
		}

		// add voices read scope to secret info
		secretInfo.AppendPermission(PermissionStrings[PronunciationDictionariesRead])
		// map resource to secret info
		for _, pd := range PDs.PronunciationDictionaries {
			secretInfo.AppendResource(ElevenLabsResource{
				ID:         pd.ID,
				Name:       pd.Name,
				Type:       "Pronunciation Dictionary",
				Permission: PermissionStrings[PronunciationDictionariesRead],
			})
		}

		return nil
	case http.StatusUnauthorized:
		return handleErrorStatus(response, "", secretInfo, MissingPermissions)
	default:
		return fmt.Errorf("unexpected status code: %d while checking pronunciation dictionaries read scope", statusCode)
	}
}

// removePronunciationDictionariesRule try to remove a rule from pronunciation dictionaries. The item must not exist.
func removePronunciationDictionariesRule(client *http.Client, key string, secretInfo *SecretInfo) error {
	// send empty list of rule strings
	payload := map[string]interface{}{
		"rule_strings": []string{""},
	}

	payloadBytes, _ := json.Marshal(payload)
	response, statusCode, err := makeElevenLabsRequestWithPayload(client, getAPIUrl(PronunciationDictionariesWrite), http.MethodPost,
		"application/json", key, payloadBytes)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusNotFound:
		// if permission was assigned to token we should get 404 error with pronunciation_dictionary_not_found status
		return handleErrorStatus(response, PermissionStrings[PronunciationDictionariesWrite], secretInfo, PronunciationDictionaryNotFound)
	case http.StatusUnauthorized:
		return handleErrorStatus(response, "", secretInfo, MissingPermissions)
	default:
		return fmt.Errorf("unexpected status code: %d while checking pronunciation dictionary write scope", statusCode)
	}
}

// getModels list models using the key passed and add them to secret info
func getModels(client *http.Client, key string, secretInfo *SecretInfo) error {
	response, statusCode, err := makeElevenLabsRequest(client, getAPIUrl(ModelsRead), http.MethodGet, key)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var models []ModelsResponse

		if err := json.Unmarshal(response, &models); err != nil {
			return err
		}

		// add models read scope to secret info
		secretInfo.AppendPermission(PermissionStrings[ModelsRead])
		// map resource to secret info
		for _, model := range models {
			secretInfo.AppendResource(ElevenLabsResource{
				ID:         model.ID,
				Name:       model.Name,
				Type:       "Model",
				Permission: PermissionStrings[ModelsRead],
			})
		}

		return nil
	case http.StatusUnauthorized:
		return handleErrorStatus(response, "", secretInfo, MissingPermissions)
	default:
		return fmt.Errorf("unexpected status code: %d while checking models read scope", statusCode)
	}
}

// updateAudioNativeProject try to update a project content. The item must not exist.
func updateAudioNativeProject(client *http.Client, key string, secretInfo *SecretInfo) error {
	// create a buffer to hold the multipart form data
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// add required fields to multipart form body
	_ = writer.WriteField("auto_convert", "false")
	_ = writer.WriteField("auto_publish", "false")
	// close the writer
	_ = writer.Close()

	response, statusCode, err := makeElevenLabsRequestWithPayload(client, getAPIUrl(AudioNativeWrite), http.MethodPost,
		writer.FormDataContentType(), key, body.Bytes())
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusBadRequest:
		// if the permission is assigned to token, the api should return 400 with invalid project id
		if err := handleErrorStatus(response, PermissionStrings[AudioNativeWrite], secretInfo, InvalidProjectID); err != nil {
			return err
		}

		// add read permission as no separate API exist to check read audio native permission
		secretInfo.AppendPermission(PermissionStrings[AudioNativeRead])
		return nil
	case http.StatusUnauthorized:
		return handleErrorStatus(response, "", secretInfo, MissingPermissions)
	default:
		return fmt.Errorf("unexpected status code: %d while checking audio native write scope", statusCode)
	}
}

// deleteInviteFromWorkspace try to remove a invite from workspace. The item must not exist.
func deleteInviteFromWorkspace(client *http.Client, key string, secretInfo *SecretInfo) error {
	// send fake email in payload
	payload := map[string]interface{}{
		"email": fakeID + "@example.com",
	}

	payloadBytes, _ := json.Marshal(payload)
	response, statusCode, err := makeElevenLabsRequestWithPayload(client, getAPIUrl(WorkspaceWrite), http.MethodDelete,
		"application/json", key, payloadBytes)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusInternalServerError:
		// for some reason if we send fake email and token has the permission, the workspace invite api return 500 error instead of 404
		if err := handleErrorStatus(response, PermissionStrings[WorkspaceWrite], secretInfo, InternalServerError); err != nil {
			return err
		}

		// add read permission as no separate API exist to check workspace read permission
		secretInfo.AppendPermission(PermissionStrings[WorkspaceRead])
		return nil
	case http.StatusUnauthorized:
		return handleErrorStatus(response, "", secretInfo, MissingPermissions)
	default:
		return fmt.Errorf("unexpected status code: %d while checking workspace write scope", statusCode)
	}
}

// textToSpeech try to convert text to speech. The model id and voice id is fake so it actually never happens.
func textToSpeech(client *http.Client, key string, secretInfo *SecretInfo) error {
	// send fake model id in payload
	payload := map[string]interface{}{
		"text":     "This is trufflehog trying to check text to speech permission of the token",
		"model_id": fakeID,
	}

	payloadBytes, _ := json.Marshal(payload)
	response, statusCode, err := makeElevenLabsRequestWithPayload(client, getAPIUrl(TextToSpeech), http.MethodPost,
		"application/json", key, payloadBytes)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusBadRequest:
		// if permission is assigned to token, error status will be either model not found or voice not found as we sent both fake ;)
		return handleErrorStatus(response, PermissionStrings[TextToSpeech], secretInfo, ModelNotFound, VoiceNotFound)
	case http.StatusUnauthorized:
		return handleErrorStatus(response, "", secretInfo, MissingPermissions)
	default:
		return fmt.Errorf("unexpected status code: %d while checking text to speech scope", statusCode)
	}
}

// speechToSpeech try to change a voice in speech. The model id and voice id is fake so it actually never happens.
func speechToSpeech(client *http.Client, key string, secretInfo *SecretInfo) error {
	// create a buffer to hold the multipart form data
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// add required fields to multipart form body
	_ = writer.WriteField("model_id", fakeID)
	_ = writer.WriteField("seed", "1")
	_ = writer.WriteField("remove_background_noise", "false")
	audio, _ := writer.CreateFormFile("audio", "")
	_, _ = audio.Write([]byte("This is example fake audio for api call"))
	// close the writer
	_ = writer.Close()

	response, statusCode, err := makeElevenLabsRequestWithPayload(client, getAPIUrl(SpeechToSpeech), http.MethodPost,
		writer.FormDataContentType(), key, body.Bytes())
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusBadRequest:
		return handleErrorStatus(response, PermissionStrings[SpeechToSpeech], secretInfo, InvalidContent)
	case http.StatusUnauthorized:
		return handleErrorStatus(response, "", secretInfo, MissingPermissions)
	default:
		return fmt.Errorf("unexpected status code: %d while checking speech to speech scope", statusCode)
	}
}

// audioIsolation try to remove background noise from a voice. The file will be corrupted so it should return an error.
func audioIsolation(client *http.Client, key string, secretInfo *SecretInfo) error {
	// create a buffer to hold the multipart form data
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	audio, _ := writer.CreateFormFile("audio", "")
	_, _ = audio.Write([]byte("This is example fake audio for api call"))
	// close the writer
	_ = writer.Close()

	response, statusCode, err := makeElevenLabsRequestWithPayload(client, getAPIUrl(AudioIsolation), http.MethodPost,
		writer.FormDataContentType(), key, body.Bytes())
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusBadRequest:
		return handleErrorStatus(response, PermissionStrings[AudioIsolation], secretInfo, InvalidContent)
	case http.StatusUnauthorized:
		return handleErrorStatus(response, "", secretInfo, MissingPermissions)
	default:
		return fmt.Errorf("unexpected status code: %d while checking audio isolation speech scope", statusCode)
	}
}

/*
getAgents get all user agents which are not bound with any permission
call APIs in pattern: agents->conversation
*/
func getAgents(client *http.Client, key string, secretInfo *SecretInfo) error {
	response, statusCode, err := makeElevenLabsRequest(client, "https://api.elevenlabs.io/v1/convai/agents", http.MethodGet, key)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var agents AgentsResponse

		if err := json.Unmarshal(response, &agents); err != nil {
			return err
		}

		// map resource to secret info
		for _, agent := range agents.Agents {
			resource := ElevenLabsResource{
				ID:         agent.ID,
				Name:       agent.Name,
				Type:       "Agent",
				Permission: "", // not binded with any permission
				Metadata: map[string]string{
					"access level": agent.AccessLevel,
				},
			}
			secretInfo.AppendResource(resource)
			// get agent conversations
			if err := getConversation(client, key, agent.ID, secretInfo); err != nil {
				return err
			}
		}

		return nil
	default:
		return fmt.Errorf("unexpected status code: %d while checking models read scope", statusCode)
	}
}

// getConversation list all agent conversations using the key and agentID passed and add them to secret info
func getConversation(client *http.Client, key, agentID string, secretInfo *SecretInfo) error {
	apiUrl := fmt.Sprintf("https://api.elevenlabs.io/v1/convai/conversations?agent_id=%s", agentID)
	response, statusCode, err := makeElevenLabsRequest(client, apiUrl, http.MethodGet, key)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var conversations ConversationResponse

		if err := json.Unmarshal(response, &conversations); err != nil {
			return err
		}

		// map resource to secret info
		for _, conversation := range conversations.Conversations {
			secretInfo.AppendResource(ElevenLabsResource{
				ID:         conversation.ID,
				Name:       "", // no name
				Type:       "Conversation",
				Permission: "", // not binded with any permission
				Metadata: map[string]string{
					"status": conversation.Status,
				},
			})
		}

		return nil
	default:
		return fmt.Errorf("unexpected status code: %d while checking models read scope", statusCode)
	}
}

// handleErrorStatus handle error response, check if expected error status is in the response and add require permission to secret info
// this is used in case where we expect error response with specific status mostly in write calls
func handleErrorStatus(response []byte, permissionToAdd string, secretInfo *SecretInfo, expectedErrStatuses ...string) error {
	// check if status in response is what is expected to be
	ok, err := checkErrorStatus(response, expectedErrStatuses...)
	if err != nil {
		return err
	}

	// if permission to add was passed and it was expected error status add the permission
	if permissionToAdd != "" && ok {
		secretInfo.AppendPermission(permissionToAdd)
	} else if permissionToAdd != "" && !ok {
		// if permission to add was passed and it was unexpected error status - return error
		return errors.New("unexpected error response")
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
