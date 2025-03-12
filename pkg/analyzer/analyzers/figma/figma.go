//go:generate generate_permissions permissions.yaml permissions.go figma

package figma

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/v6/table"

	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

var _ analyzers.Analyzer = (*Analyzer)(nil)

type Analyzer struct {
	Cfg *config.Config
}

func (Analyzer) Type() analyzers.AnalyzerType { return analyzers.AnalyzerTypeFigma }

type ScopeStatus string

const (
	StatusError      ScopeStatus = "Error"
	StatusGranted    ScopeStatus = "Granted"
	StatusDenied     ScopeStatus = "Denied"
	StatusUnverified ScopeStatus = "Unverified"
)

func (a Analyzer) Analyze(_ context.Context, credInfo map[string]string) (*analyzers.AnalyzerResult, error) {
	token, ok := credInfo["token"]
	if !ok {
		return nil, errors.New("token not found in credInfo")
	}
	info, err := AnalyzePermissions(a.Cfg, token)
	if err != nil {
		return nil, err
	}
	return MapToAnalyzerResult(info), nil
}

func AnalyzeAndPrintPermissions(cfg *config.Config, token string) {
	info, err := AnalyzePermissions(cfg, token)
	if err != nil {
		color.Red("[x] Error : %s", err.Error())
		return
	}

	color.Green("[!] Valid Figma Personal Access Token\n\n")
	PrintUserAndPermissions(info)
}

func AnalyzePermissions(cfg *config.Config, token string) (*SecretInfo, error) {
	client := analyzers.NewAnalyzeClient(cfg)
	allScopes := getAllScopes()
	var info = &SecretInfo{Scopes: map[Scope]ScopeStatus{}}
	for _, scope := range allScopes {
		info.Scopes[scope] = StatusUnverified
	}

	for _, scope := range orderedScopeList {
		resp, err := callEndpointByScope(client, token, scope)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		validationResult, err := validateTokenScopesFromResponse(resp, scope)
		if err != nil {
			return nil, err
		}
		if validationResult.Status == StatusGranted {
			if scope == ScopeFilesRead {
				if err := json.NewDecoder(resp.Body).Decode(&info.UserInfo); err != nil {
					return nil, fmt.Errorf("error decoding user info from response %v", err)
				}
			}
			info.Scopes[scope] = StatusGranted
		}
		// If the token does NOT have the scope, response will include all the scopes it does have
		if validationResult.Status == StatusDenied {
			for s := range info.Scopes {
				info.Scopes[s] = StatusDenied
			}
			for _, s := range validationResult.Scopes {
				info.Scopes[s] = StatusGranted
			}
			// We have enough info to finish analysis
			break
		}
	}
	return info, nil
}

// validateTokenScopesFromResponse takes the API response and validates through it whether
// the access token has the required scope to perform that action.
// It returns a validation result object which contains the status of scope for the token, and an error
// In case the status is StatusDenied, it also returns all the scopes which are StatusGranted
func validateTokenScopesFromResponse(resp *http.Response, scope Scope) (ScopeValidationResult, error) {
	endpoint, err := getScopeEndpoint(scope)
	if err != nil {
		return ScopeValidationResult{Status: StatusUnverified}, err
	}

	respStatus := resp.StatusCode
	if respStatus == http.StatusOK {
		return ScopeValidationResult{Status: StatusGranted}, nil
	}

	// If the response was not a success, we will validate the error object
	var errorResponse APIErrorResponse
	if err := json.NewDecoder(resp.Body).Decode(&errorResponse); err != nil {
		return ScopeValidationResult{Status: StatusUnverified}, err
	}

	expectedResponse := endpoint.ExpectedResponseWithScope
	if respStatus == expectedResponse.Status {
		if errorResponse.Message == expectedResponse.Message {
			return ScopeValidationResult{Status: StatusGranted}, nil
		}
	}

	expectedError := endpoint.ExpectedResponseWithoutScope
	scopeStrings, scopeIsDenied := validateErrorAndGetScopes(errorResponse, expectedError)
	if scopeIsDenied {
		scopes := getScopesFromScopeStrings(scopeStrings)
		return ScopeValidationResult{Status: StatusDenied, Scopes: scopes}, nil
	}

	// Can not determine scope as the expected error is unknown
	return ScopeValidationResult{Status: StatusUnverified}, nil
}

// Matches API response with expected API response in case token has missing scope
// If the responses match, we can extract all available scopes from the response msg
func validateErrorAndGetScopes(errorResp APIErrorResponse, expectedResp APIErrorResponse) ([]string, bool) {
	if errorResp.Status != expectedResp.Status {
		return nil, false
	}

	if errorResp.Err != "" {
		return matchMessageWithExpectedMessage(errorResp.Err, expectedResp.Err)
	}
	if errorResp.Message != "" {
		return matchMessageWithExpectedMessage(errorResp.Message, expectedResp.Message)
	}

	return nil, false
}

func matchMessageWithExpectedMessage(msg string, expectedMsg string) ([]string, bool) {
	cleanedMsg := cleanUpErrorResponseMessage(msg)
	re := regexp.MustCompile(expectedMsg)
	matches := re.FindStringSubmatch(cleanedMsg)

	// If we have a match, extract the scopes
	if len(matches) > 1 {
		scopes := strings.Split(matches[1], ", ") // Split by ", " to get individual scopes
		return scopes, true
	}

	return nil, false
}

// The cleanUpErrorResponseMessage function cleans the provided "invalid permission" API
// response message by removing the characters '"', '[', ']', '\', and '"'.
func cleanUpErrorResponseMessage(msg string) string {
	result := strings.ReplaceAll(msg, "\\", "")
	result = strings.ReplaceAll(msg, "\"", "")
	result = strings.ReplaceAll(result, "[", "")
	result = strings.ReplaceAll(result, "]", "")
	return result
}

func MapToAnalyzerResult(info *SecretInfo) *analyzers.AnalyzerResult {
	if info == nil {
		return nil
	}

	result := analyzers.AnalyzerResult{
		AnalyzerType: analyzers.AnalyzerTypeFigma,
	}
	var permissions []analyzers.Permission
	for scope, status := range info.Scopes {
		if status != StatusGranted {
			continue
		}
		permissions = append(permissions, analyzers.Permission{Value: string(scope)})
	}
	userResource := analyzers.Resource{
		Name:               info.UserInfo.Handle,
		FullyQualifiedName: info.UserInfo.ID,
		Type:               "user",
		Metadata: map[string]any{
			"email":   info.UserInfo.Email,
			"img_url": info.UserInfo.ImgURL,
		},
	}

	result.Bindings = analyzers.BindAllPermissions(userResource, permissions...)
	return &result
}

func PrintUserAndPermissions(info *SecretInfo) {
	color.Yellow("[i] User Info:")
	t1 := table.NewWriter()
	t1.SetOutputMirror(os.Stdout)
	t1.AppendHeader(table.Row{"ID", "Handle", "Email", "Image URL"})
	t1.AppendRow(table.Row{
		color.GreenString(info.UserInfo.ID),
		color.GreenString(info.UserInfo.Handle),
		color.GreenString(info.UserInfo.Email),
		color.GreenString(info.UserInfo.ImgURL),
	})
	t1.SetOutputMirror(os.Stdout)
	t1.Render()

	color.Yellow("\n[i] Scopes:")
	t2 := table.NewWriter()
	t2.AppendHeader(table.Row{"Scope", "Status", "Actions"})
	for scope, status := range info.Scopes {
		actions := getScopeActions(scope)
		rows := []table.Row{}
		for i, action := range actions {
			var scopeCell string
			var statusCell string
			if i == 0 {
				scopeCell = color.GreenString(string(scope))
				statusCell = color.GreenString(string(status))
			}
			rows = append(rows, table.Row{scopeCell, statusCell, color.GreenString(action)})
		}
		t2.AppendRows(rows)
		t2.AppendSeparator()
	}
	t2.SetOutputMirror(os.Stdout)
	t2.Render()
	fmt.Printf("%s: https://www.figma.com/developers/api\n\n", color.GreenString("Ref"))
}
