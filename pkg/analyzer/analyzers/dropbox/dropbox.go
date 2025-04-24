//go:generate generate_permissions permissions.yaml permissions.go dropbox
package dropbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/v6/table"

	_ "embed"

	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

var _ analyzers.Analyzer = (*Analyzer)(nil)

//go:embed scopes.json
var scopeConfigJson []byte

type Analyzer struct {
	Cfg *config.Config
}
type PermissionStatus string

const (
	StatusGranted    PermissionStatus = "Granted"
	StatusDenied     PermissionStatus = "Denied"
	StatusUnverified PermissionStatus = "Unverified"
)

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
	printAccountAndPermissions(info)
}

func AnalyzePermissions(cfg *config.Config, token string) (*secretInfo, error) {
	// Dropbox API uses POST requests for all requests, so we need to use an unrestricted client
	client := analyzers.NewAnalyzeClientUnrestricted(cfg)
	scopeConfigMap, err := getScopeConfigMap()
	if err != nil {
		return nil, err
	}

	secretInfo := &secretInfo{}

	accountInfoPermission := PermissionStrings[AccountInfoRead]
	for _, perm := range PermissionStrings {
		scopeDetails := scopeConfigMap.Scopes[perm]
		status := StatusUnverified
		if perm == accountInfoPermission {
			// Account Info Read permission is always enabled
			status = StatusGranted
		}
		secretInfo.Permissions = append(secretInfo.Permissions, accountPermission{
			Name:    perm,
			Status:  status,
			Actions: scopeDetails.Actions,
		})
	}

	if err := populateAccountInfo(client, secretInfo, token); err != nil {
		return nil, err
	}

	if err := testAllPermissions(client, secretInfo, scopeConfigMap, token); err != nil {
		return nil, err
	}

	return secretInfo, nil
}

func populateAccountInfo(client *http.Client, info *secretInfo, token string) error {
	endpoint := "/2/users/get_current_account"
	body, statusCode, err := callDropboxAPIEndpoint(client, endpoint, token)
	if err != nil {
		return err
	}
	switch statusCode {
	case http.StatusOK:
		if err := json.Unmarshal([]byte(body), &info.Account); err != nil {
			return fmt.Errorf("failed to unmarshal account info: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("failed to validate scope. Status %d: %s", statusCode, body)
	}
}

func testAllPermissions(client *http.Client, info *secretInfo, scopeConfigMap *scopeConfig, token string) error {
	permissionStatuses := make(map[string]PermissionStatus)

	for _, perm := range PermissionStrings {
		scopeDetails := scopeConfigMap.Scopes[perm]

		if _, ok := permissionStatuses[perm]; ok || scopeDetails.TestEndpoint == "" {
			// Skip if the scope has already been determined or has no test endpoint
			continue
		}

		if perm == PermissionStrings[Openid] {
			// The OpenID permission can be validated using the "/2/users/get_current_account" endpoint
			// If the response contains the "email" key, that implies that the "email" permission is also granted
			// Similar case for the "given_name" key and the "profile" permission
			body, statusCode, err := callDropboxAPIEndpoint(client, scopeDetails.TestEndpoint, token)
			if err != nil {
				return err
			}
			switch statusCode {
			case http.StatusOK, http.StatusConflict:
				// The endpoint responds with 409 Conflict if the openid scope
				// is granted but the email and profile scopes are not granted
				permissionStatuses[perm] = StatusGranted

				// Check for the "email" key in the response body
				if strings.Contains(body, "\"email\":") {
					permissionStatuses[PermissionStrings[Email]] = StatusGranted
				} else {
					permissionStatuses[PermissionStrings[Email]] = StatusDenied
				}

				// Check for the "given_name" key in the response body
				if strings.Contains(body, "\"given_name\":") {
					permissionStatuses[PermissionStrings[Profile]] = StatusGranted
				} else {
					permissionStatuses[PermissionStrings[Profile]] = StatusDenied
				}
			case http.StatusUnauthorized:
				permissionStatuses[perm] = StatusDenied
				permissionStatuses[PermissionStrings[Email]] = StatusDenied
				permissionStatuses[PermissionStrings[Profile]] = StatusDenied
			}
			continue
		}

		isGranted, err := testPermission(client, scopeDetails.TestEndpoint, token)
		if err != nil {
			return err
		}

		if !isGranted {
			permissionStatuses[perm] = StatusDenied
			continue
		}

		permissionStatuses[perm] = StatusGranted
		for _, impliedScope := range scopeDetails.ImpliedScopes {
			permissionStatuses[impliedScope] = StatusGranted
		}
	}

	for idx, permission := range info.Permissions {
		permission.Status = permissionStatuses[permission.Name]
		info.Permissions[idx] = permission
	}

	return nil
}

func testPermission(client *http.Client, testEndpoint string, token string) (bool, error) {
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
	return false, fmt.Errorf("failed to validate scope. Status %d: %s", statusCode, body)
}

func callDropboxAPIEndpoint(client *http.Client, endpoint string, token string) (string, int, error) {
	baseURL := "https://api.dropboxapi.com"
	req, err := http.NewRequest(http.MethodPost, baseURL+endpoint, nil)
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

func getScopeConfigMap() (*scopeConfig, error) {
	var scopeConfigMap scopeConfig
	if err := json.Unmarshal(scopeConfigJson, &scopeConfigMap); err != nil {
		return nil, errors.New("failed to unmarshal scopes.json: " + err.Error())
	}
	return &scopeConfigMap, nil
}

func secretInfoToAnalyzerResult(info *secretInfo) *analyzers.AnalyzerResult {
	if info == nil {
		return nil
	}

	account := info.Account
	accountID := account.AccountID
	allPermissions := getValidatedPermissions(info)

	resource := analyzers.Resource{
		Name:               fmt.Sprintf("%s %s", account.Name.GivenName, account.Name.Surname),
		FullyQualifiedName: accountID,
		Type:               "account",
		Metadata: map[string]any{
			"email":         account.Email,
			"emailVerified": account.EmailVerified,
			"disabled":      account.Disabled,
			"country":       account.Country,
			"accountType":   account.AccountType.Tag,
		},
	}
	analyzers.BindAllPermissions(resource, allPermissions...)
	result := analyzers.AnalyzerResult{
		AnalyzerType: analyzers.AnalyzerTypeDropbox,
		Metadata:     nil,
		Bindings:     analyzers.BindAllPermissions(resource, allPermissions...),
	}
	return &result
}

func getValidatedPermissions(info *secretInfo) []analyzers.Permission {
	permissions := []analyzers.Permission{}

	for _, permission := range info.Permissions {
		if permission.Status != StatusGranted {
			continue
		}
		permissions = append(permissions, analyzers.Permission{
			Value: permission.Name,
		})
	}

	return permissions
}

func printAccountAndPermissions(info *secretInfo) {
	color.Yellow("\n[i] Accounts Info:")
	t1 := table.NewWriter()
	t1.SetOutputMirror(os.Stdout)
	t1.AppendHeader(table.Row{"ID", "Name", "Email", "Email Verified", "Disabled", "Country", "Account Type"})
	emailVerified := "No"
	disabled := "No"
	if info.Account.EmailVerified {
		emailVerified = "Yes"
	}
	if info.Account.Disabled {
		disabled = "Yes"
	}
	t1.AppendRow(table.Row{
		color.GreenString(info.Account.AccountID),
		color.GreenString(info.Account.Name.GivenName + " " + info.Account.Name.Surname),
		color.GreenString(info.Account.Email),
		color.GreenString(emailVerified),
		color.GreenString(disabled),
		color.GreenString(info.Account.Country),
		color.GreenString(info.Account.AccountType.Tag),
	})
	t1.SetOutputMirror(os.Stdout)
	t1.Render()

	color.Yellow("\n[i] Permissions:")
	t2 := table.NewWriter()
	t2.AppendHeader(table.Row{"Permission", "Access", "Actions"})

	permissions := info.Permissions
	for _, permission := range permissions {
		access := "Denied"
		permissionStatus := permission.Status
		if permissionStatus == StatusGranted {
			access = "Granted"
		}
		if permissionStatus == StatusUnverified {
			access = "Unverified"
		}
		for idx, action := range permission.Actions {
			permissionCell := ""
			accessCell := ""
			if idx == 0 {
				permissionCell = color.GreenString(permission.Name)
				accessCell = color.GreenString(access)
			}

			t2.AppendRow(table.Row{
				permissionCell,
				accessCell,
				action,
			})
		}
		t2.AppendSeparator()
	}

	t2.SetOutputMirror(os.Stdout)
	t2.Render()
	fmt.Printf("%s: https://www.dropbox.com/developers/documentation\n\n", color.GreenString("Ref"))
}
