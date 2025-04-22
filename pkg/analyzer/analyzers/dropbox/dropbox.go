//go:generate generate_permissions permissions.yaml permissions.go dropbox
package dropbox

import (
	// 	"bytes"
	// 	"encoding/json"
	// 	"errors"
	// 	"fmt"
	// 	"net/http"
	// 	"os"
	// 	"strings"

	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/fatih/color"
	// "github.com/jedib0t/go-pretty/v6/table"

	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

var _ analyzers.Analyzer = (*Analyzer)(nil)

type Analyzer struct {
	Cfg *config.Config
}

type resourceDetails struct {
	Name        string
	DisplayName string
}

func (a Analyzer) Type() analyzers.AnalyzerType {
	return analyzers.AnalyzerTypeDropbox
}

func (a Analyzer) Analyze(_ context.Context, credInfo map[string]string) (*analyzers.AnalyzerResult, error) {
	token, exist := credInfo["token"]
	if !exist {
		return nil, errors.New("token not found in credentials info")
	}

	info, err := AnalyzePermissions(a.Cfg, token)
	if err != nil {
		return nil, err
	}

	return secretInfoToAnalyzerResult(info), nil
}

func AnalyzeAndPrintPermissions(cfg *config.Config, token string) {
	info, err := AnalyzePermissions(cfg, token)
	if err != nil {
		color.Red("[x] Invalid Dropbox Token\n")
		color.Red("[x] Error : %s", err.Error())
		return
	}

	if info == nil {
		color.Red("[x] Error : %s", "No information found")
		return
	}

	color.Green("[i] Valid Dropbox OAuth2 Credentials\n")
	// printAccountsAndProducts(info)
}

func AnalyzePermissions(cfg *config.Config, token string) (*secretInfo, error) {
	// Dropbox API uses POST requests for all requests, so we need to use an unrestricted client
	client := analyzers.NewAnalyzeClient(cfg)

	secretInfo := &secretInfo{
		Permissions: make(map[string]PermissionStatus),
	}
	scopeConfigMap, err := getScopeConfigMap()
	if err != nil {
		return nil, err
	}

	for _, perm := range PermissionStrings {
		
		secretInfo.Permissions[perm] = StatusUnverified
	}
	accountInfoReadString, ok := PermissionStrings[AccountsInfoRead]
	if !ok {
		return nil, errors.New("invalid scope or config doesn't exist")
	}
	// Account Info Read permission is always enabled
	secretInfo.Permissions[accountInfoReadString] = StatusGranted

	accountInfo, err := getAccountInfo(client, token)
	if err != nil {
		return nil, err
	}
	secretInfo.Account = accountInfo

	validatedPermissions, err := getPermissions(client, scopeConfigMap, token)
	if err != nil {
		return nil, err
	}
	for _, scope := range validatedPermissions {

		secretInfo.Permissions[scope] = StatusGranted
	}

	return secretInfo, nil
}

func getAccountInfo(client *http.Client, token string) (account, error) {
	url := "https://api.dropboxapi.com/2/users/get_current_account"
	body, statusCode, err := callDropboxAPIEndpoint(client, url, token)
	if err != nil {
		return account{}, err
	}
	switch statusCode {
	case http.StatusOK:
		var accountInfo account
		if err := json.Unmarshal([]byte(body), &accountInfo); err != nil {
			return account{}, fmt.Errorf("failed to unmarshal account info: %w", err)
		}
		return accountInfo, nil
	default:
		return account{}, fmt.Errorf("failed to validate scope. Status %s: %s", statusCode, body)
	}
}

func getPermissions(client *http.Client, scopeConfigMap *scopeConfig, token string) ([]string, error) {
	validatedPermissions := make([]string, 0)
	individualScopeLists := [][]scope{
		scopeConfigMap.AccountScopes,
		scopeConfigMap.FilesContentScopes,
		scopeConfigMap.FilesMetadataScopes,
		scopeConfigMap.SharingScopes,
		scopeConfigMap.FileRequestsScopes,
		scopeConfigMap.ContactsScopes,
	}

	for _, scopeList := range individualScopeLists {
		for _, scope := range scopeList {
			if contains(validatedPermissions, scope.Name) || scope.TestEndpoint == "" {
				// Skip if the scope is already validated or if the test endpoint is not defined
				continue
			}

			isValid, err := validatePermission(client, scope.TestEndpoint, token)
			if err != nil {
				return nil, err
			}
			if isValid {
				// Add the scope name to the validated permissions list
				validatedPermissions = append(validatedPermissions, scope.Name)
				// Add all implied scopes to the validated permissions list as well
				for _, impliedScope := range scope.ImpliedScopes {
					if !contains(validatedPermissions, impliedScope) {
						validatedPermissions = append(validatedPermissions, impliedScope)
					}
				}
			}
		}
	}

	for _, scope := range scopeConfigMap.OpenIDScopes {
		if contains(validatedPermissions, scope.Name) || scope.TestEndpoint == "" {
			continue
		}
		// Open ID permission can be validated using the /2/users/get_current_account endpoint
		// If the response contains the "email" key, that implies that the email permission is also granted
		// Similar case for the "given_name" key and the profile permission
		body, statusCode, err := callDropboxAPIEndpoint(client, scope.TestEndpoint, token)
		if err != nil {
			return nil, err
		}
		switch statusCode {
		case http.StatusOK, http.StatusConflict:
			validatedPermissions = append(validatedPermissions, scope.Name)
			if strings.Contains(body, "\"email\": \"") {
				validatedPermissions = append(validatedPermissions, PermissionStrings[Email])
			}
			if strings.Contains(body, "\"given_name\": \"") {
				validatedPermissions = append(validatedPermissions, PermissionStrings[Profile])
			}
		case http.StatusUnauthorized:
			break
		default:
			return nil, fmt.Errorf("failed to validate OpenID scope. Status %s: %s", statusCode, body)
		}
	}

	return validatedPermissions, nil
}

func validatePermission(client *http.Client, testEndpoint string, token string) (bool, error) {
	body, statusCode, err := callDropboxAPIEndpoint(client, testEndpoint, token)
	if err != nil {
		return false, err
	}

	switch statusCode {
	case http.StatusUnauthorized:
		return false, nil
	case http.StatusBadRequest:
		if strings.Contains(body, "does not have the required scope") {
			return false, nil
		}
		if strings.Contains(body, "your request body is empty") {
			return true, nil
		}
	}
	return false, fmt.Errorf("failed to validate scope. Status %s: %s", statusCode, body)
}

func callDropboxAPIEndpoint(client *http.Client, endpoint string, token string) (string, int, error) {
	req, err := http.NewRequest(http.MethodPost, endpoint, nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}

	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	bodyBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return "", 0, fmt.Errorf("failed to read response body: %w", err)
	}

	return string(bodyBytes), res.StatusCode, nil
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func secretInfoToAnalyzerResult(info *secretInfo) *analyzers.AnalyzerResult {
	if info == nil {
		return nil
	}

	account := info.Account
	accountID := account.AccountID
	// scopes := info.Permissions

	result := analyzers.AnalyzerResult{
		AnalyzerType: analyzers.AnalyzerTypeDropbox,
		Metadata:     nil,
		Bindings:     []analyzers.Binding{},
		UnboundedResources: []analyzers.Resource{{
			Name:               fmt.Sprintf("%s %s", account.Name.GivenName, account.Name.Surname),
			FullyQualifiedName: account.AccountID,
			Type:               "account",
			Metadata: map[string]any{
				"email":         account.Email,
				"emailVerified": account.EmailVerified,
				"disabled":      account.Disabled,
				"country":       account.Country,
				"accountType":   account.AccountType.Tag,
			},
		}},
	}

	resourceDetails := getResourceDetails()
	for 

	for {
		if status == StatusDenied {
			continue
		}
		result.Bindings = append(result.Bindings, analyzers.Binding{
			Resource: analyzers.Resource{
				Name:               resource.DisplayName,
				FullyQualifiedName: accountID + "/resource/" + resource.Name,
				Type:               "resource",
			},
			Permission: analyzers.Permission{
				Value: string(status),
			},
		})
	}

	return &result
}

func createResource(name string, displayName string, accountID string) analyzers.Resource {
	return analyzers.Resource{
		Name:               displayName,
		FullyQualifiedName: accountID + "/resource/" + name,
		Type:               "resource",
	}
}

func getResourceDetails() []resourceDetails {
	return []resourceDetails{
		{Name: "account_info", DisplayName: "Account Info"},
		{Name: "files_metadata", DisplayName: "Files Metadata"},
		{Name: "files_content", DisplayName: "Files Content"},
		{Name: "sharing", DisplayName: "Sharing"},
		{Name: "file_requests", DisplayName: "File Requests"},
		{Name: "contacts", DisplayName: "Contacts"},
		{Name: "openid", DisplayName: "OpenID"},
	}
}

// func printAccountsAndProducts(info *secretInfo) {
// 	userProducts := info.Item.Products
// 	userAccounts := info.Accounts

// 	color.Yellow("\n[i] Item ID: %s", info.Item.ItemID)

// 	color.Yellow("\n[i] Accounts Info:")
// 	t1 := table.NewWriter()
// 	t1.SetOutputMirror(os.Stdout)
// 	t1.AppendHeader(table.Row{"ID", "Name", "Official Name", "Type", "Subtype"})
// 	for _, account := range userAccounts {
// 		t1.AppendRow(table.Row{
// 			color.GreenString(account.AccountID),
// 			color.GreenString(account.Name),
// 			color.GreenString(account.OfficialName),
// 			color.GreenString(account.Type),
// 			color.GreenString(account.Subtype),
// 		})
// 		t1.AppendSeparator()
// 	}
// 	t1.SetOutputMirror(os.Stdout)
// 	t1.Render()

// 	color.Yellow("\n[i] Products:")
// 	t2 := table.NewWriter()
// 	t2.AppendHeader(table.Row{"Product Name", "Access Level", "Capabilities"})

// 	for _, product := range plaidProducts {
// 		productCell := color.GreenString(product.DisplayName)
// 		productDescCell := color.GreenString(product.Description)
// 		productPermissionCell := color.GreenString("Denied")

// 		for _, productName := range userProducts {
// 			if productName == product.Name {
// 				permissionLevel := PermissionStrings[product.PermissionLevel]
// 				productPermissionCell = "Granted" // If permission level is not defined, default to "Granted"
// 				if len(permissionLevel) > 0 {
// 					// Capitalize the perssion level string
// 					capitalizedLevel := strings.ToUpper(string(permissionLevel[0])) + strings.ToLower(permissionLevel[1:])
// 					productPermissionCell = color.GreenString(capitalizedLevel)
// 				}
// 				break
// 			}
// 		}

// 		t2.AppendRow(table.Row{productCell, productPermissionCell, productDescCell})
// 		t2.AppendSeparator()
// 	}

// 	t2.SetOutputMirror(os.Stdout)
// 	t2.Render()
// 	fmt.Printf("%s: https://plaid.com/docs/api/\n\n", color.GreenString("Ref"))
// }
