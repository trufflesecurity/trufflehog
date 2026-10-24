//go:generate generate_permissions permissions.yaml permissions.go xai
package xai

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/v6/table"

	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

var _ analyzers.Analyzer = (*Analyzer)(nil)

const (
	resourceTypeTeam     = "team"
	resourceTypeEndpoint = "endpoint"
	resourceTypeModel    = "model"
)

type Analyzer struct {
	Cfg *config.Config
}

// SecretInfo holds the information about the xAI API key.
type SecretInfo struct {
	Valid     bool
	Key       apiKeyResponse
	Team      XAIResource
	Endpoints []XAIResource
	Models    []XAIResource
	// ACLs that are not in the documented api-key:<kind>:<name> form.
	UnknownACLs []string
}

// XAIResource is any resource that can be accessed with an xAI API key.
type XAIResource struct {
	ID       string
	Name     string
	Type     string
	Metadata map[string]string
}

func (a Analyzer) Type() analyzers.AnalyzerType {
	return analyzers.AnalyzerTypeXAI
}

func (a Analyzer) Analyze(ctx context.Context, credInfo map[string]string) (*analyzers.AnalyzerResult, error) {
	key, exist := credInfo["key"]
	if !exist {
		err := errors.New("key not found in credentials info")
		return nil, analyzers.NewAnalysisError(a.Type().String(), analyzers.OperationValidateCredentials, analyzers.ServiceConfig, "", err)
	}

	secretInfo, err := AnalyzePermissions(ctx, a.Cfg, key)
	if err != nil {
		return nil, analyzers.NewAnalysisError(a.Type().String(), analyzers.OperationAnalyzePermissions, analyzers.ServiceAPI, "", err)
	}

	return secretInfoToAnalyzerResult(secretInfo), nil
}

func AnalyzeAndPrintPermissions(cfg *config.Config, key string) {
	info, err := AnalyzePermissions(context.Background(), cfg, key)
	if err != nil {
		color.Red("[x] Error : %s", err.Error())
		return
	}

	printKeyInfo(info)
	if !info.Valid {
		return
	}

	printResources("Endpoints", info.Endpoints)
	printResources("Models", info.Models)

	if len(info.UnknownACLs) > 0 {
		color.Yellow("\n[i] Unrecognized ACLs: %s", strings.Join(info.UnknownACLs, ", "))
	}
}

func AnalyzePermissions(ctx context.Context, cfg *config.Config, key string) (*SecretInfo, error) {
	return analyzePermissions(ctx, analyzers.NewAnalyzeClient(cfg), key)
}

func analyzePermissions(ctx context.Context, client *http.Client, key string) (*SecretInfo, error) {
	keyInfo, err := fetchAPIKeyInfo(ctx, client, key)
	if err != nil {
		return nil, err
	}

	secretInfo := &SecretInfo{
		Key: *keyInfo,
		Team: XAIResource{
			ID:   "x.ai/team/" + keyInfo.TeamID,
			Name: keyInfo.TeamID,
			Type: resourceTypeTeam,
		},
		// The key endpoint answers 200 for blocked and disabled keys too, but
		// such keys cannot call the API.
		Valid: !keyInfo.APIKeyBlocked && !keyInfo.APIKeyDisabled && !keyInfo.TeamBlocked,
	}
	if !secretInfo.Valid {
		return secretInfo, nil
	}

	allowedEndpoints, allowedModels, unknown := parseACLs(keyInfo.ACLs)
	secretInfo.UnknownACLs = unknown

	for _, endpoint := range allowedEndpoints {
		secretInfo.Endpoints = append(secretInfo.Endpoints, XAIResource{
			ID:   fmt.Sprintf("x.ai/team/%s/endpoint/%s", keyInfo.TeamID, endpoint),
			Name: endpoint,
			Type: resourceTypeEndpoint,
		})
	}

	models, listed, err := fetchModels(ctx, client, key)
	if err != nil {
		return nil, err
	}
	secretInfo.Models = accessibleModels(keyInfo.TeamID, allowedModels, models, listed)

	return secretInfo, nil
}

// accessibleModels intersects the models the API lists with the models the
// key's ACLs allow. Models named in the ACLs but absent from the listing are
// still reported, since the ACL alone grants access to them.
func accessibleModels(teamID string, allowed []string, listedModels []model, listed bool) []XAIResource {
	wildcard := slices.Contains(allowed, aclWildcard)
	matched := make(map[string]bool, len(allowed))
	var resources []XAIResource

	if listed {
		for _, m := range listedModels {
			names := append([]string{m.ID}, m.Aliases...)
			isAllowed := wildcard
			for _, name := range names {
				if slices.Contains(allowed, name) {
					matched[name] = true
					isAllowed = true
				}
			}
			if !isAllowed {
				continue
			}

			metadata := map[string]string{"owned_by": m.OwnedBy}
			if len(m.Aliases) > 0 {
				metadata["aliases"] = strings.Join(m.Aliases, ",")
			}
			if m.ContextLength != nil {
				metadata["context_length"] = strconv.Itoa(*m.ContextLength)
			}

			resources = append(resources, XAIResource{
				ID:       fmt.Sprintf("x.ai/team/%s/model/%s", teamID, m.ID),
				Name:     m.ID,
				Type:     resourceTypeModel,
				Metadata: metadata,
			})
		}
	}

	for _, name := range allowed {
		if matched[name] || (listed && name == aclWildcard) {
			continue
		}
		resources = append(resources, XAIResource{
			ID:   fmt.Sprintf("x.ai/team/%s/model/%s", teamID, name),
			Name: name,
			Type: resourceTypeModel,
		})
	}

	return resources
}

func secretInfoToAnalyzerResult(info *SecretInfo) *analyzers.AnalyzerResult {
	if info == nil {
		return nil
	}

	result := analyzers.AnalyzerResult{
		AnalyzerType: analyzers.AnalyzerTypeXAI,
		Metadata: map[string]any{
			"Valid_Key":        info.Valid,
			"key_name":         info.Key.Name,
			"api_key_id":       info.Key.APIKeyID,
			"redacted_api_key": info.Key.RedactedAPIKey,
			"user_id":          info.Key.UserID,
			"team_id":          info.Key.TeamID,
			"acls":             strings.Join(info.Key.ACLs, ","),
			"api_key_blocked":  info.Key.APIKeyBlocked,
			"api_key_disabled": info.Key.APIKeyDisabled,
			"team_blocked":     info.Key.TeamBlocked,
			"create_time":      info.Key.CreateTime,
			"modify_time":      info.Key.ModifyTime,
		},
		Bindings: make([]analyzers.Binding, 0, len(info.Endpoints)+len(info.Models)),
	}

	team := analyzers.Resource{
		Name:               info.Team.Name,
		FullyQualifiedName: info.Team.ID,
		Type:               info.Team.Type,
	}

	addBindings := func(resources []XAIResource, permission Permission) {
		for _, res := range resources {
			metadata := make(map[string]any, len(res.Metadata))
			for k, v := range res.Metadata {
				metadata[k] = v
			}
			result.Bindings = append(result.Bindings, analyzers.Binding{
				Resource: analyzers.Resource{
					Name:               res.Name,
					FullyQualifiedName: res.ID,
					Type:               res.Type,
					Metadata:           metadata,
					Parent:             &team,
				},
				Permission: analyzers.Permission{Value: PermissionStrings[permission]},
			})
		}
	}
	addBindings(info.Endpoints, EndpointAccess)
	addBindings(info.Models, ModelAccess)

	return &result
}

func printKeyInfo(info *SecretInfo) {
	if info.Valid {
		color.Green("[!] Valid xAI API Key\n\n")
	} else {
		color.Red("[x] xAI API Key exists but cannot be used (blocked: %t, disabled: %t, team blocked: %t)\n\n",
			info.Key.APIKeyBlocked, info.Key.APIKeyDisabled, info.Key.TeamBlocked)
	}

	color.Yellow("[i] Key Information:")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Name", "Key ID", "Redacted Key", "Team ID", "User ID", "Created"})
	t.AppendRow(table.Row{
		color.GreenString(info.Key.Name),
		color.GreenString(info.Key.APIKeyID),
		color.GreenString(info.Key.RedactedAPIKey),
		color.GreenString(info.Key.TeamID),
		color.GreenString(info.Key.UserID),
		color.GreenString(info.Key.CreateTime),
	})
	t.Render()
}

func printResources(title string, resources []XAIResource) {
	color.Green("\n[i] %s:", title)
	if len(resources) == 0 {
		color.Yellow("None")
		return
	}

	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Name", "Fully Qualified Name"})
	for _, res := range resources {
		t.AppendRow(table.Row{color.GreenString(res.Name), color.GreenString(res.ID)})
	}
	t.Render()
}
