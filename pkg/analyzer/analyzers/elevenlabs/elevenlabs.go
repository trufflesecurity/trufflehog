package elevenlabs

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"slices"

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
	Permissions []string   // list of Permissions assigned to the key
	Resources   []Resource // list of resources the key has access to
	Misc        map[string]string
}

// User hold the information about user to whom the key belongs to
type User struct {
	ID                 string
	Name               string
	SubscriptionTier   string
	SubscriptionStatus string
}

// Resources hold information about the resources the key has access
type Resource struct {
	ID         string
	Name       string
	Type       string
	Metadata   map[string]string
	Permission string
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

	// validate the key and get user information
	valid, err := validateKey(client, key, secretInfo)
	if err != nil {
		return nil, err
	}

	if !valid {
		return nil, errors.New("key is not valid")
	}

	// Get resources
	if err := getResources(client, key, secretInfo); err != nil {
		return nil, nil
	}

	return secretInfo, nil
}

func AnalyzeAndPrintPermissions(cfg *config.Config, key string) {
	info, err := AnalyzePermissions(cfg, key)
	if err != nil {
		color.Red("[x] Error : %s", err.Error())
		return
	}

	if info == nil {
		color.Red("[x] Error : %s", "No information found")
		return
	}

	if info.Valid {
		color.Green("[!] Valid ElevenLabs API key\n\n")
		// print user information
		printUser(info.User)
		// print permissions
		printPermissions(info.Permissions)
		// print resources
		printResources(info.Resources)

		color.Yellow("\n[i] Expires: Never")
	}
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

	// extract information from resource to create bindings and append to result bindings
	for _, resource := range info.Resources {
		binding := analyzers.Binding{
			Resource: analyzers.Resource{
				Name:               resource.Name,
				FullyQualifiedName: resource.ID,
				Type:               resource.Type,
			},
			Permission: analyzers.Permission{
				Value: resource.Permission,
			},
		}

		for key, value := range resource.Metadata {
			binding.Resource.Metadata[key] = value
		}

		result.Bindings = append(result.Bindings, binding)
	}

	result.Metadata["Valid_Key"] = info.Valid

	return &result
}

// validateKey check if the key is valid and get the user information if it's valid
func validateKey(client *http.Client, key string, secretInfo *SecretInfo) (bool, error) {
	response, statusCode, err := makeElevenLabsRequest(client, permissionToAPIMap[UserRead], http.MethodGet, key)
	if err != nil {
		return false, err
	}

	if statusCode == http.StatusOK {
		var user UserResponse

		if err := json.Unmarshal(response, &user); err != nil {
			return false, err
		}

		// map info to secretInfo
		secretInfo.Valid = true
		secretInfo.User = User{
			ID:                 user.UserID,
			Name:               user.FirstName,
			SubscriptionTier:   user.Subscription.Tier,
			SubscriptionStatus: user.Subscription.Status,
		}
		// add user read scope to secret info
		secretInfo.Permissions = append(secretInfo.Permissions, PermissionStrings[UserRead])
		// map resource to secret info
		secretInfo.Resources = append(secretInfo.Resources, Resource{
			ID:         user.UserID,
			Name:       user.FirstName,
			Type:       "User",
			Permission: PermissionStrings[UserRead],
		})

		return true, nil
	} else if statusCode >= http.StatusBadRequest && statusCode <= 499 {
		// check if api key is invalid or not verifiable, return false
		ok, err := checkErrorStatus(response, InvalidAPIKey, NotVerifiable)
		if err != nil {
			return false, err
		}

		if ok {
			return false, nil
		}
	}

	// if no expected status code was detected
	return false, fmt.Errorf("unexpected status code: %d", statusCode)
}

/*
getResources gather resources the key can access

Note: The permissions in eleven labs is either Read or Read and Write. There is not separate permission for Write.
If a particular write permission exist that means the read also exist.
So for API calls that does not return any resource data, we make the write permissions API calls first
and if they were as expected we skip the read API calls and add read permission directly.
If write permission API calls was not as expected than only we make read permission API calls
This we only do for those API calls which does not add any resources to secretInfo
*/
func getResources(client *http.Client, key string, secretInfo *SecretInfo) error {
	// history
	if err := getHistory(client, key, secretInfo); err != nil {
		return err
	}

	if err := deleteHistory(client, key, secretInfo); err != nil {
		return err
	}

	// dubbings
	if err := deleteDubbing(client, key, secretInfo); err != nil {
		return err
	}

	// if dubbing write permission was not added
	if !permissionExist(secretInfo.Permissions, DubbingWrite) {
		if err := getDebugging(client, key, secretInfo); err != nil {
			return err
		}
	}

	// voices
	if err := getVoices(client, key, secretInfo); err != nil {
		return err
	}

	if err := deleteVoice(client, key, secretInfo); err != nil {
		return err
	}

	// projects
	if err := getProjects(client, key, secretInfo); err != nil {
		return err
	}

	if err := deleteProject(client, key, secretInfo); err != nil {
		return err
	}

	// pronunciation dictionaries
	if err := getPronunciationDictionaries(client, key, secretInfo); err != nil {
		return err
	}

	if err := removePronunciationDictionariesRule(client, key, secretInfo); err != nil {
		return err
	}

	// models
	if err := getModels(client, key, secretInfo); err != nil {
		return err
	}

	// audio native
	if err := updateAudioNativeProject(client, key, secretInfo); err != nil {
		return err
	}

	// workspace
	if err := deleteInviteFromWorkspace(client, key, secretInfo); err != nil {
		return err
	}

	// text to speech
	// voice changer
	// audio isolation

	return nil
}

// permissionExist returns if particular permission exist in the list
func permissionExist(permissionsList []string, permission Permission) bool {
	permissionString, _ := permission.ToString()

	return slices.Contains(permissionsList, permissionString)
}

// cli print functions
func printUser(user User) {
	color.Green("\n[i] User:")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"ID", "Name", "Subscription Tier", "Subscription Status"})
	t.AppendRow(table.Row{color.GreenString(user.ID), color.GreenString(user.Name), color.GreenString(user.SubscriptionTier), color.GreenString(user.SubscriptionStatus)})
	t.Render()
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

func printResources(resources []Resource) {
	color.Green("\n[i] Resources:")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Resource Type", "Resource ID", "Resource Name", "Permission"})
	for _, resource := range resources {
		t.AppendRow(table.Row{color.GreenString(resource.Type), color.GreenString(resource.ID), color.GreenString(resource.Name), color.GreenString(resource.Permission)})
	}
	t.Render()
}
