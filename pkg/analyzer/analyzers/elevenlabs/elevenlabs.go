package elevenlabs

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/table"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

var _ analyzers.Analyzer = (*Analyzer)(nil)

type Analyzer struct {
	Cfg *config.Config
}

// SecretInfo hold information about key
type SecretInfo struct {
	User        User // the owner of key
	Valid       bool
	Reference   string
	Permissions []string  // list of Permissions assigned to the key
	Resources   Resources // list of resources the key has access to
	Misc        map[string]string
}

func (a Analyzer) Type() analyzers.AnalyzerType {
	return analyzers.AnalyzerTypeElevenLabs
}

func (a Analyzer) Analyze(_ context.Context, credInfo map[string]string) (*analyzers.AnalyzerResult, error) {
	// check if the `key` exist in the credentials info
	key, exist := credInfo["key"]
	if !exist {
		return nil, errors.New("key not found in credentials info")
	}

	info, err := AnalyzePermissions(a.Cfg, key)
	if err != nil {
		return nil, err
	}

	return secretInfoToAnalyzerResult(info), nil
}

// AnalyzePermissions check if key is valid and analyzes the permission for the key
func AnalyzePermissions(cfg *config.Config, key string) (*SecretInfo, error) {
	// create http client
	client := analyzers.NewAnalyzeClient(cfg)

	var secretInfo = &SecretInfo{}

	// valide the key and get user information
	secretInfo, valid, err := validateKey(client, key, secretInfo)
	if err != nil {
		return nil, err
	}

	if !valid {
		return nil, errors.New("key is not valid")
	}

	return secretInfo, nil
}

func AnalyzeAndPrintPermissions(cfg *config.Config, key string) {
	info, err := AnalyzePermissions(cfg, key)
	if err != nil {
		color.Red("[x] Error : %s", err.Error())
		return
	}

	if info.Valid {
		color.Green("[!] Valid ElevenLabs API key\n\n")
	}
	printPermissions(info.Permissions)
	if info.Valid {
		printUser(info.User)
	}
	color.Yellow("\n[i] Expires: Never")

}

// secretInfoToAnalyzerResult translate secret info to Analyzer Result
func secretInfoToAnalyzerResult(info *SecretInfo) *analyzers.AnalyzerResult {
	if info == nil {
		return nil
	}

	result := analyzers.AnalyzerResult{
		AnalyzerType: analyzers.AnalyzerTypeElevenLabs,
		Metadata:     map[string]any{},
		Bindings:     make([]analyzers.Binding, len(info.Permissions)),
	}

	for id, scope := range info.Permissions {
		result.Bindings[id] = analyzers.Binding{
			Permission: analyzers.Permission{
				Value: scope,
			},
		}
	}
	result.Metadata["Valid_Key"] = info.Valid

	return &result
}

// validateKey check if the key is valid and get the user information if it's valid
func validateKey(client *http.Client, key string, secretInfo *SecretInfo) (*SecretInfo, bool, error) {
	response, statusCode, err := makeGetRequest(client, permissionToAPIMap[UserRead], key)
	if err != nil {
		return nil, false, err
	}

	if statusCode == http.StatusOK {
		var user UserResponse

		if err := json.Unmarshal(response, &user); err != nil {
			return nil, false, err
		}

		// map info to secretInfo
		secretInfo.Valid = true
		secretInfo.User.ID = user.UserID
		secretInfo.User.Name = user.FirstName
		secretInfo.User.SubscriptionTier = user.Subscription.Tier
		secretInfo.User.SubscriptionStatus = user.Subscription.Status
		// add user read scope to secret info
		secretInfo.Permissions = append(secretInfo.Permissions, PermissionStrings[UserRead])

		return secretInfo, true, nil
	} else if statusCode >= http.StatusBadRequest && statusCode <= 499 {
		// check if api key is invalid or not verifiable, return false
		ok, err := checkErrorStatus(response, InvalidAPIKey, NotVerifiable)
		if err != nil {
			return nil, false, err
		}

		if ok {
			return nil, false, nil
		}
	}

	// if no expected status code was detected
	return nil, false, fmt.Errorf("unexpected status code: %d", statusCode)
}

// CaptureBindings gather permissions assigned to key and the resources it has access to
func CaptureBindings(client *http.Client, key string, secretInfo *SecretInfo) (*SecretInfo, error) {
	// history item ids
	// dubbings
	// voices
	// projects
	// samples
	// pronunciation dictionaries
	// models
	// audio native
	// text to speech
	// voice changer
	// audio isolation

	return nil, nil
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

func printPermissions(permissions []string) {
	color.Yellow("[i] Permissions:")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Permission"})
	for _, permission := range permissions {
		t.AppendRow(table.Row{color.GreenString(permission)})
	}
	t.Render()
}

func printUser(user User) {
	color.Green("\n[i] User:")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"ID", "Name", "Subscription Tier", "Subscription Status"})
	t.AppendRow(table.Row{color.GreenString(user.ID), color.GreenString(user.Name), color.GreenString(user.SubscriptionTier), color.GreenString(user.SubscriptionStatus)})
	t.Render()
}
