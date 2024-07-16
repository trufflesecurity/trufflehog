package huggingface

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/table"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/pb/analyzerpb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/pb/resourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

const (
	FINEGRAINED = "fineGrained"
	WRITE       = "write"
	READ        = "read"
)

var _ analyzers.Analyzer = (*Analyzer)(nil)

type Analyzer struct {
	Cfg *config.Config
}

func (Analyzer) Type() analyzerpb.SecretType { return analyzerpb.SecretType_HUGGINGFACE }

func (a Analyzer) Analyze(_ context.Context, key string, _ map[string]string) (*analyzers.AnalyzerResult, error) {
	info, err := AnalyzePermissions(a.Cfg, key)
	if err != nil {
		return nil, err
	}
	return secretInfoToAnalyzerResult(info), nil
}

func secretInfoToAnalyzerResult(info *SecretInfo) *analyzers.AnalyzerResult {
	if info == nil {
		return nil
	}

	// Token  HFTokenJSON
	//	Username string
	//	Name     string
	//	Orgs
	//		Name         string
	//		Role         string
	//		IsEnterprise bool
	//	Auth
	//		AccessToken
	//			Name        string
	//			Type        string
	//			CreatedAt   string
	//			FineGrained
	//				Global []string
	//				Scoped []struct
	//					Entity
	//						Type string
	//						Name string
	//						ID   string
	//					Permissions []string
	// Models []Model
	//	   Name        string
	//	   ID          string
	//	   Private     bool
	//	   Permissions Permissions
	//		   Read  bool
	//		   Write bool

	result := analyzers.AnalyzerResult{
		SecretMetadata: map[string]string{
			"name":       info.Token.Auth.AccessToken.Name,
			"type":       info.Token.Auth.AccessToken.Type,
			"created_at": info.Token.Auth.AccessToken.CreatedAt,
		},
	}

	for _, model := range info.Models {
		rp := analyzers.ResourcePermission{
			ResourceTree: analyzers.ResourceTree{
				Resource: &resourcespb.Resource{
					SecretType:   analyzerpb.SecretType_HUGGINGFACE,
					ResourceType: resourcespb.ResourceType_MODEL,
					Name:         model.Name,
					Metadata: map[string]string{
						"id":      model.ID,
						"private": strconv.FormatBool(model.Private),
					},
				},
			},
			Permissions: convertModelPermissions(model.Permissions),
		}

		result.ResourcePermissions = append(result.ResourcePermissions, rp)
	}

	return &result
}

// convertModelPermissions converts a model Permissions struct into a slice of
// analyzers.Permission.
func convertModelPermissions(perms Permissions) []analyzers.Permission {
	var permissions []analyzers.Permission
	if perms.Read {
		// TODO: Is this the right string?
		permissions = append(permissions, analyzers.Permission("read"))
	}
	if perms.Write {
		// TODO: Is this the right string?
		permissions = append(permissions, analyzers.Permission("write"))
	}
	return permissions
}

// HFTokenJSON is the struct for the HF /whoami-v2 API JSON response
type HFTokenJSON struct {
	Username string `json:"name"`
	Name     string `json:"fullname"`
	Orgs     []struct {
		Name         string `json:"name"`
		Role         string `json:"roleInOrg"`
		IsEnterprise bool   `json:"isEnterprise"`
	} `json:"orgs"`
	Auth struct {
		AccessToken struct {
			Name        string `json:"displayName"`
			Type        string `json:"role"`
			CreatedAt   string `json:"createdAt"`
			FineGrained struct {
				Global []string `json:"global"`
				Scoped []struct {
					Entity struct {
						Type string `json:"type"`
						Name string `json:"name"`
						ID   string `json:"_id"`
					} `json:"entity"`
					Permissions []string `json:"permissions"`
				} `json:"scoped"`
			} `json:"fineGrained"`
		}
	} `json:"auth"`
}

type Permissions struct {
	Read  bool
	Write bool
}

type Model struct {
	Name        string `json:"id"`
	ID          string `json:"_id"`
	Private     bool   `json:"private"`
	Permissions Permissions
}

// getModelsByAuthor calls the HF API /models endpoint with the author query param
// returns a list of models and an error
func getModelsByAuthor(cfg *config.Config, key string, author string) ([]Model, error) {
	var modelsJSON []Model

	// create a new request
	client := analyzers.NewAnalyzeClient(cfg)
	req, err := http.NewRequest("GET", "https://huggingface.co/api/models", nil)
	if err != nil {
		return modelsJSON, err
	}

	// Add bearer token
	req.Header.Add("Authorization", "Bearer "+key)

	// Add author param
	q := req.URL.Query()
	q.Add("author", author)
	req.URL.RawQuery = q.Encode()

	// send the request
	resp, err := client.Do(req)
	if err != nil {
		return modelsJSON, err
	}

	// defer the response body closing
	defer resp.Body.Close()

	// read response
	if err := json.NewDecoder(resp.Body).Decode(&modelsJSON); err != nil {
		return modelsJSON, err
	}
	return modelsJSON, nil
}

// getTokenInfo calls the HF API /whoami-v2 endpoint to get the token info
// returns the token info, a boolean indicating token validity, and an error
func getTokenInfo(cfg *config.Config, key string) (HFTokenJSON, bool, error) {
	var tokenJSON HFTokenJSON

	// create a new request
	client := analyzers.NewAnalyzeClient(cfg)
	req, err := http.NewRequest("GET", "https://huggingface.co/api/whoami-v2", nil)
	if err != nil {
		return tokenJSON, false, err
	}

	// Add bearer token
	req.Header.Add("Authorization", "Bearer "+key)

	// send the request
	resp, err := client.Do(req)
	if err != nil {
		return tokenJSON, false, err
	}

	// check if the response is 200
	if resp.StatusCode != 200 {
		return tokenJSON, false, nil
	}

	// defer the response body closing
	defer resp.Body.Close()

	// read response
	if err := json.NewDecoder(resp.Body).Decode(&tokenJSON); err != nil {
		return tokenJSON, true, err
	}
	return tokenJSON, true, nil
}

type SecretInfo struct {
	Token  HFTokenJSON
	Models []Model
}

func AnalyzePermissions(cfg *config.Config, key string) (*SecretInfo, error) {
	// get token info
	token, success, err := getTokenInfo(cfg, key)
	if err != nil {
		return nil, err
	}

	if !success {
		return nil, fmt.Errorf("Invalid HuggingFace Access Token")
	}

	// get all models by username
	var allModels []Model
	userModels, err := getModelsByAuthor(cfg, key, token.Username)
	if err != nil {
		return nil, err
	}
	allModels = append(allModels, userModels...)

	// get all models from all orgs
	for _, org := range token.Orgs {
		orgModels, err := getModelsByAuthor(cfg, key, org.Name)
		if err != nil {
			return nil, err
		}
		allModels = append(allModels, orgModels...)
	}

	return &SecretInfo{
		Token:  token,
		Models: allModels,
	}, nil
}

// AnalyzePermissions prints the permissions of a HuggingFace API key
func AnalyzeAndPrintPermissions(cfg *config.Config, key string) {
	info, err := AnalyzePermissions(cfg, key)
	if err != nil {
		color.Red("[x] Error: %s", err.Error())
		return
	}

	color.Green("[!] Valid HuggingFace Access Token\n\n")

	// print user info
	color.Yellow("[i] Username: " + info.Token.Username)
	color.Yellow("[i] Name: " + info.Token.Name)
	color.Yellow("[i] Token Name: " + info.Token.Auth.AccessToken.Name)
	color.Yellow("[i] Token Type: " + info.Token.Auth.AccessToken.Type)

	// print org info
	printOrgs(info.Token)

	// print accessible models
	printAccessibleModels(info.Models, info.Token)

	if info.Token.Auth.AccessToken.Type == FINEGRAINED {
		// print org permissions
		printOrgPermissions(info.Token)

		// print user permissions
		printUserPermissions(info.Token)
	}
}

// printUserPermissions prints the user permissions
// only applies to fine-grained tokens
func printUserPermissions(tokenJSON HFTokenJSON) {
	color.Green("\n[i] User Permissions:")

	// build a map of all user permissions
	userPermissions := map[string]struct{}{}
	for _, permission := range tokenJSON.Auth.AccessToken.FineGrained.Scoped {
		if permission.Entity.Type == "user" {
			for _, perm := range permission.Permissions {
				userPermissions[perm] = struct{}{}
			}
		}
	}

	// global permissions only apply to user tokens as of 6/6/24
	// but there would be a naming collision in the scopes document
	// so we prepend "global." to the key and then add to the map
	for _, permission := range tokenJSON.Auth.AccessToken.FineGrained.Global {
		userPermissions["global."+permission] = struct{}{}
	}

	// check if there are any user permissions
	if len(userPermissions) == 0 {
		color.Red("\tNo user permissions scoped.")
		return
	}

	// print the user permissions
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Category", "Permission", "In-Scope"})

	for _, permission := range user_scopes_order {
		t.AppendRow([]interface{}{permission, "---", "---"})
		for key, value := range user_scopes[permission] {
			if _, ok := userPermissions[key]; ok {
				t.AppendRow([]interface{}{"", color.GreenString(value), color.GreenString("True")})
			} else {
				t.AppendRow([]interface{}{"", value, "False"})
			}
		}
	}
	t.Render()
}

// printOrgPermissions prints the organization permissions
// only applies to fine-grained tokens
func printOrgPermissions(tokenJSON HFTokenJSON) {
	color.Green("\n[i] Organization Permissions:")

	// check if there are any org permissions
	// if so, save them as a map. Only need to do this once
	// even if multiple orgs b/c as of 6/6/24, users can only define one set of scopes
	// for all orgs referenced on an access token
	orgScoped := false
	orgPermissions := map[string]struct{}{}
	for _, permission := range tokenJSON.Auth.AccessToken.FineGrained.Scoped {
		if permission.Entity.Type == "org" {
			orgScoped = true
			for _, perm := range permission.Permissions {
				orgPermissions[perm] = struct{}{}
			}
			break
		}
	}

	// check if there are any org permissions
	if !orgScoped {
		color.Red("\tNo organization permissions scoped.")
		return
	}

	// print the org permissions
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Category", "Permission", "In-Scope"})

	for _, permission := range org_scopes_order {
		t.AppendRow([]interface{}{permission, "---", "---"})
		for key, value := range org_scopes[permission] {
			if _, ok := orgPermissions[key]; ok {
				t.AppendRow([]interface{}{"", color.GreenString(value), color.GreenString("True")})
			} else {
				t.AppendRow([]interface{}{"", value, "False"})
			}
		}
	}
	t.Render()
}

// printOrgs prints the organizations the user is a member of
func printOrgs(tokenJSON HFTokenJSON) {
	color.Green("\n[i] Organizations:")

	if len(tokenJSON.Orgs) == 0 {
		color.Yellow("\tNo organizations found.")
		return
	}

	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Name", "Role", "Is Enterprise"})
	for _, org := range tokenJSON.Orgs {
		enterprise := ""
		role := ""
		if org.IsEnterprise {
			enterprise = color.New(color.FgGreen).Sprintf("True")
		} else {
			enterprise = "False"
		}
		if org.Role == "admin" {
			role = color.New(color.FgGreen).Sprintf("Admin")
		} else {
			role = org.Role
		}
		t.AppendRow([]interface{}{color.GreenString(org.Name), role, enterprise})
	}
	t.Render()
}

// modelNameLookup is a helper function to lookup model name by _id
func modelNameLookup(models []Model, id string) string {
	for _, model := range models {
		if model.ID == id {
			return model.Name
		}
	}
	return ""
}

// printAccessibleModels adds permissions as needed to each model
//
//	and then calls the printModelsTable function
func printAccessibleModels(allModels []Model, tokenJSON HFTokenJSON) {
	color.Green("\n[i] Accessible Models:")

	if tokenJSON.Auth.AccessToken.Type != FINEGRAINED {
		// Add Read Privs to All Models
		for idx := range allModels {
			allModels[idx].Permissions.Read = true
		}
		// Add Write Privs to All Models if Write Access
		if tokenJSON.Auth.AccessToken.Type == WRITE {
			for idx := range allModels {
				allModels[idx].Permissions.Write = true
			}
		}
		// Print Models Table
		printModelsTable(allModels)
		return
	}

	// finegrained scopes are grouped by org, user or model.
	// this section will extract the relevant permissions for each entity and store them in a map
	var nameToPermissions = make(map[string]Permissions)
	for _, permission := range tokenJSON.Auth.AccessToken.FineGrained.Scoped {
		read := false
		write := false
		for _, perm := range permission.Permissions {
			if perm == "repo.content.read" {
				read = true
			} else if perm == "repo.write" {
				write = true
			}
		}
		if permission.Entity.Type == "user" || permission.Entity.Type == "org" {
			nameToPermissions[permission.Entity.Name] = Permissions{Read: read, Write: write}
		} else if permission.Entity.Type == "model" {
			nameToPermissions[modelNameLookup(allModels, permission.Entity.ID)] = Permissions{Read: read, Write: write}
		}
	}

	// apply permissions to all models
	for idx := range allModels {
		// get username/orgname for each model and apply those permissions
		modelUsername := strings.Split(allModels[idx].Name, "/")[0]
		if permissions, ok := nameToPermissions[modelUsername]; ok {
			allModels[idx].Permissions = permissions
		}
		// override model permissions with repo-specific permissions
		if permissions, ok := nameToPermissions[allModels[idx].Name]; ok {
			allModels[idx].Permissions = permissions
		}
	}

	// Print Models Table
	printModelsTable(allModels)
}

// printModelsTable prints the models table
func printModelsTable(models []Model) {
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Model", "Private", "Read", "Write"})
	for _, model := range models {
		var name, read, write, private string
		if model.Permissions.Read {
			read = color.New(color.FgGreen).Sprintf("True")
		} else {
			read = "False"
		}
		if model.Permissions.Write {
			write = color.New(color.FgGreen).Sprintf("True")
		} else {
			write = "False"
		}
		if model.Private {
			private = color.New(color.FgGreen).Sprintf("True")
			name = color.New(color.FgGreen).Sprintf(model.Name)
		} else {
			private = "False"
			name = model.Name
		}
		t.AppendRow([]interface{}{name, private, read, write})
	}
	t.Render()
}
