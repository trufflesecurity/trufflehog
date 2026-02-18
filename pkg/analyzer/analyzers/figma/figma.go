//go:generate generate_permissions permissions.yaml permissions.go figma

package figma

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
		return nil, analyzers.NewAnalysisError("Figma", "validate_credentials", "config", "", errors.New("token not found in credInfo"))
	}
	info, err := AnalyzePermissions(a.Cfg, token)
	if err != nil {
		return nil, analyzers.NewAnalysisError("Figma", "analyze_permissions", "API", "", err)
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

func AnalyzePermissions(cfg *config.Config, token string) (*secretInfo, error) {
	client := analyzers.NewAnalyzeClient(cfg)
	allScopes := getAllScopes()
	scopeToEndpoints, err := getScopeEndpointsMap()
	if err != nil {
		return nil, err
	}

	var info = &secretInfo{Scopes: map[Scope]ScopeStatus{}}
	for _, scope := range allScopes {
		info.Scopes[scope] = StatusUnverified
	}

	for _, scope := range orderedScopeList {
		endpoint, err := getScopeEndpoint(scopeToEndpoints, scope)
		if err != nil {
			return nil, err
		}
		resp, err := callAPIEndpoint(client, token, endpoint)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}

		scopeStatus := determineScopeStatus(resp.StatusCode, endpoint)
		if scopeStatus == StatusGranted {
			if scope == ScopeFilesRead {
				if err := json.Unmarshal(body, &info.UserInfo); err != nil {
					return nil, fmt.Errorf("error decoding user info from response %v", err)
				}
			}
			info.Scopes[scope] = StatusGranted
		}
		// If the token does NOT have the scope, response will include all the scopes it does have
		if scopeStatus == StatusDenied {
			scopes, ok := extractScopesFromError(body)
			if !ok {
				return nil, fmt.Errorf("could not extract scopes from error message")
			}
			for scope := range info.Scopes {
				info.Scopes[scope] = StatusDenied
			}
			for _, scope := range scopes {
				info.Scopes[scope] = StatusGranted
			}
			// We have enough info to finish analysis
			break
		}
	}
	return info, nil
}

// determineScopeStatus takes the API response status code and uses it along with the expected
// status codes to dermine whether the access token has the required scope to perform that action.
// It returns a ScopeStatus which can be Granted, Denied, or Unverified.
func determineScopeStatus(statusCode int, endpoint endpoint) ScopeStatus {
	if statusCode == endpoint.ExpectedStatusCodeWithScope || statusCode == http.StatusOK {
		return StatusGranted
	}

	if statusCode == endpoint.ExpectedStatusCodeWithoutScope {
		return StatusDenied
	}

	// Can not determine scope as the expected error is unknown
	return StatusUnverified
}

// Matches API response body with expected message pattern in case the token is missing a scope
// If the responses match, we can extract all available scopes from the response msg
func extractScopesFromError(body []byte) ([]Scope, bool) {
	filteredBody := filterErrorResponseBody(string(body))
	re := regexp.MustCompile(`Invalid scope(?:\(s\))?: ([a-zA-Z_:, ]+)\. This endpoint requires.*`)
	matches := re.FindStringSubmatch(filteredBody)
	if len(matches) > 1 {
		scopes := strings.Split(matches[1], ", ")
		return getScopesFromScopeStrings(scopes), true
	}
	return nil, false
}

// The filterErrorResponseBody function cleans the provided "invalid permission" API
// response message by removing the characters '"', '[', ']', '\', and '"'.
func filterErrorResponseBody(msg string) string {
	result := strings.ReplaceAll(msg, "\\", "")
	result = strings.ReplaceAll(result, "\"", "")
	result = strings.ReplaceAll(result, "[", "")
	return strings.ReplaceAll(result, "]", "")
}

func MapToAnalyzerResult(info *secretInfo) *analyzers.AnalyzerResult {
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

func PrintUserAndPermissions(info *secretInfo) {
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
