package elevenlabs

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"

	"github.com/fatih/color"
	"github.com/google/uuid"
	"github.com/jedib0t/go-pretty/v6/table"

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
	User                User // the owner of key
	Valid               bool
	Reference           string
	Permissions         []string             // list of Permissions assigned to the key
	ElevenLabsResources []ElevenLabsResource // list of resources the key has access to
	mu                  sync.RWMutex
}

// AppendPermission safely append new permission to secret info permissions list.
func (s *SecretInfo) AppendPermission(perm string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.Permissions = append(s.Permissions, perm)
}

// HasPermission safely read secret info permission list to check if passed permission exist in the list.
func (s *SecretInfo) HasPermission(perm Permission) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	permissionString, _ := perm.ToString()

	return slices.Contains(s.Permissions, permissionString)
}

// AppendResource safely append new resource to secret info elevenlabs resource list.
func (s *SecretInfo) AppendResource(resource ElevenLabsResource) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.ElevenLabsResources = append(s.ElevenLabsResources, resource)
}

// User hold the information about user to whom the key belongs to
type User struct {
	ID                 string
	Name               string
	SubscriptionTier   string
	SubscriptionStatus string
}

// ElevenLabsResource hold information about the elevenlabs resource the key has access
type ElevenLabsResource struct {
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

	// fetch user information using the key
	user, err := fetchUser(client, key)
	if err != nil {
		return nil, err
	}

	secretInfo.Valid = true

	// if user is not nil, that means the key has user read permission. Set the user information in secret info user
	// user can only be nil when the key is valid but it does not have a user read permission
	if user != nil {
		elevenLabsUserToSecretInfoUser(*user, secretInfo)
	}

	// get elevenlabs resources with permissions
	if err := getElevenLabsResources(client, key, secretInfo); err != nil {
		return nil, err
	}

	return secretInfo, nil
}

func AnalyzeAndPrintPermissions(cfg *config.Config, key string) {
	info, err := AnalyzePermissions(cfg, key)
	if err != nil {
		// just print the error in cli and continue as a partial success
		color.Red("[x] Error : %s", err.Error())
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
		printElevenLabsResources(info.ElevenLabsResources)

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
		Bindings:     make([]analyzers.Binding, 0),
	}

	// for resources to be uniquely identified, we need a unique id to be appended in resource fully qualified name
	uniqueId := info.User.ID
	if uniqueId == "" {
		uniqueId = uuid.NewString()
	}

	// extract information from resource to create bindings and append to result bindings
	for _, resource := range info.ElevenLabsResources {
		// if resource has permission it is binded resource
		if resource.Permission != "" {
			binding := analyzers.Binding{
				Resource: analyzers.Resource{
					Name:               resource.Name,
					FullyQualifiedName: fmt.Sprintf("%s/%s/%s", uniqueId, resource.Type, resource.ID), // e.g: <user_id>/Model/eleven_flash_v2_5
					Type:               resource.Type,
					Metadata:           map[string]any{}, // to avoid panic
				},
				Permission: analyzers.Permission{
					Value: resource.Permission,
				},
			}

			for key, value := range resource.Metadata {
				binding.Resource.Metadata[key] = value
			}

			result.Bindings = append(result.Bindings, binding)
		} else {
			// if resource is missing permission it is an unbounded resource
			unboundedResource := analyzers.Resource{
				Name:               resource.Name,
				FullyQualifiedName: fmt.Sprintf("%s/%s/%s", uniqueId, resource.Type, resource.ID),
				Type:               resource.Type,
				Metadata:           map[string]any{},
			}

			for key, value := range resource.Metadata {
				unboundedResource.Metadata[key] = value
			}

			result.UnboundedResources = append(result.UnboundedResources, unboundedResource)
		}
	}

	result.Metadata["Valid_Key"] = info.Valid

	return &result
}

// fetchUser fetch elevenlabs user information associated with the key
func fetchUser(client *http.Client, key string) (*User, error) {
	response, statusCode, err := makeElevenLabsRequest(client, permissionToAPIMap[UserRead], http.MethodGet, key)
	if err != nil {
		return nil, err
	}

	switch statusCode {
	case http.StatusOK:
		var user UserResponse

		if err := json.Unmarshal(response, &user); err != nil {
			return nil, err
		}

		return &User{
			ID:                 user.UserID,
			Name:               user.FirstName,
			SubscriptionTier:   user.Subscription.Tier,
			SubscriptionStatus: user.Subscription.Status,
		}, nil
	case http.StatusUnauthorized:
		var errorResp ErrorResponse

		if err := json.Unmarshal(response, &errorResp); err != nil {
			return nil, err
		}

		if errorResp.Detail.Status == InvalidAPIKey || errorResp.Detail.Status == NotVerifiable {
			return nil, errors.New("invalid api key")
		} else if errorResp.Detail.Status == MissingPermissions {
			// key is missing user read permissions but is valid
			return nil, nil
		}

		return nil, nil
	default:
		return nil, fmt.Errorf("unexpected status code: %d", statusCode)
	}
}

// elevenLabsUserToSecretInfoUser set the elevenlabs user information to secretInfo user
func elevenLabsUserToSecretInfoUser(user User, secretInfo *SecretInfo) {
	secretInfo.User = user
	// add user read scope to secret info
	secretInfo.Permissions = append(secretInfo.Permissions, PermissionStrings[UserRead])
	// map resource to secret info
	// as user is accessible through a specific permission and has a unique id it is also a resource
	secretInfo.ElevenLabsResources = append(secretInfo.ElevenLabsResources, ElevenLabsResource{
		ID:         user.ID,
		Name:       user.Name,
		Type:       "User",
		Permission: PermissionStrings[UserRead],
	})
}

/*
getElevenLabsResources gather resources the key can access

Note: The permissions in eleven labs is either Read or Read and Write. There is not separate permission for Write.
*/
func getElevenLabsResources(client *http.Client, key string, secretInfo *SecretInfo) error {
	var (
		aggregatedErrs = make([]string, 0)
		errChan        = make(chan error, 17) // buffer for 17 errors - one per API call
		wg             sync.WaitGroup
	)

	// history
	wg.Add(1)
	go func() {
		defer wg.Done()

		if err := getHistory(client, key, secretInfo); err != nil {
			errChan <- err
		}

		if err := deleteHistory(client, key, secretInfo); err != nil {
			errChan <- err
		}
	}()

	// dubbings
	wg.Add(1)
	go func() {
		defer wg.Done()

		if err := deleteDubbing(client, key, secretInfo); err != nil {
			errChan <- err
		}

		// if dubbing write permission was not added
		if !secretInfo.HasPermission(DubbingWrite) {
			if err := getDebugging(client, key, secretInfo); err != nil {
				errChan <- err
			}
		}
	}()

	// voices
	wg.Add(1)
	go func() {
		defer wg.Done()

		if err := getVoices(client, key, secretInfo); err != nil {
			errChan <- err
		}

		if err := deleteVoice(client, key, secretInfo); err != nil {
			errChan <- err
		}
	}()

	// projects
	wg.Add(1)
	go func() {
		defer wg.Done()

		if err := getProjects(client, key, secretInfo); err != nil {
			errChan <- err
		}

		if err := deleteProject(client, key, secretInfo); err != nil {
			errChan <- err
		}
	}()

	// pronunciation dictionaries
	wg.Add(1)
	go func() {
		defer wg.Done()

		if err := getPronunciationDictionaries(client, key, secretInfo); err != nil {
			errChan <- err
		}

		if err := removePronunciationDictionariesRule(client, key, secretInfo); err != nil {
			errChan <- err
		}
	}()

	// models
	wg.Add(1)
	go func() {
		defer wg.Done()

		if err := getModels(client, key, secretInfo); err != nil {
			errChan <- err
		}
	}()

	// audio native
	wg.Add(1)
	go func() {
		defer wg.Done()

		if err := updateAudioNativeProject(client, key, secretInfo); err != nil {
			errChan <- err
		}
	}()

	// workspace
	wg.Add(1)
	go func() {
		defer wg.Done()

		if err := deleteInviteFromWorkspace(client, key, secretInfo); err != nil {
			errChan <- err
		}
	}()

	// speech
	wg.Add(1)
	go func() {
		defer wg.Done()

		if err := textToSpeech(client, key, secretInfo); err != nil {
			errChan <- err
		}

		// voice changer
		if err := speechToSpeech(client, key, secretInfo); err != nil {
			errChan <- err
		}
	}()

	// audio isolation
	wg.Add(1)
	go func() {
		defer wg.Done()

		if err := audioIsolation(client, key, secretInfo); err != nil {
			errChan <- err
		}
	}()

	// agent
	wg.Add(1)
	go func() {
		defer wg.Done()

		// each agent can have a conversations which we get inside this function
		if err := getAgents(client, key, secretInfo); err != nil {
			errChan <- err
		}
	}()

	// wait for all API calls to finish
	wg.Wait()
	close(errChan)

	// collect all errors
	for err := range errChan {
		aggregatedErrs = append(aggregatedErrs, err.Error())
	}

	if len(aggregatedErrs) > 0 {
		return errors.New(strings.Join(aggregatedErrs, ", "))
	}

	return nil
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

func printElevenLabsResources(resources []ElevenLabsResource) {
	color.Green("\n[i] Resources:")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Resource Type", "Resource ID", "Resource Name", "Permission"})
	for _, resource := range resources {
		t.AppendRow(table.Row{color.GreenString(resource.Type), color.GreenString(resource.ID), color.GreenString(resource.Name), color.GreenString(resource.Permission)})
	}
	t.Render()
}
