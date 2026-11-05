//go:generate generate_permissions permissions.yaml permissions.go baseten
package baseten

import (
	"errors"
	"net/http"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/v6/table"

	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

var _ analyzers.Analyzer = (*Analyzer)(nil)

const (
	resourceTypeOrganization = "organization"
	resourceTypeTeam         = "team"
	resourceTypeModel        = "model"
	resourceTypeAPIKey       = "api_key"
)

// Key categories, matching the API key types in
// https://docs.baseten.co/organization/api-keys#api-key-types.
const (
	categoryPersonal     = "personal"
	categoryTeam         = "team"
	categoryOrganization = "organization"
	categoryUnknown      = "unknown"
)

// API key types as returned by GET /v1/api_keys.
const (
	keyTypePersonal      = "PERSONAL"
	keyTypeGrid          = "GRID"
	keyTypeManageAll     = "WORKSPACE_MANAGE_ALL"
	keyTypeInvoke        = "WORKSPACE_INVOKE"
	keyTypeExportMetrics = "WORKSPACE_EXPORT_METRICS"
	keyTypeManageAPIKeys = "WORKSPACE_MANAGE_API_KEYS"
)

var keyTypePermissions = map[string]Permission{
	keyTypePersonal:      FullAccess,
	keyTypeGrid:          Invoke,
	keyTypeManageAll:     ManageAll,
	keyTypeInvoke:        Invoke,
	keyTypeExportMetrics: ExportMetrics,
	keyTypeManageAPIKeys: ManageApiKeys,
}

type Analyzer struct {
	Cfg *config.Config
}

// SecretInfo holds the information about the Baseten API key.
type SecretInfo struct {
	User         userResponse
	Organization *organizationResponse
	Category     string
	// Key is the key's own metadata. It is nil when the key may not list API
	// keys, which is the case for team keys.
	Key *apiKeyInfo
	// OtherKeys are the other API keys the key can see. Only organization keys
	// can manage them.
	OtherKeys []apiKeyInfo
}

func (a Analyzer) Type() analyzers.AnalyzerType {
	return analyzers.AnalyzerTypeBaseten
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

	color.Green("[!] Valid Baseten API Key\n\n")
	printKeyInfo(info)

	if info.Category == categoryOrganization {
		printAPIKeys(info.OtherKeys)
	}
}

func AnalyzePermissions(ctx context.Context, cfg *config.Config, key string) (*SecretInfo, error) {
	return analyzePermissions(ctx, analyzers.NewAnalyzeClient(cfg), key)
}

func analyzePermissions(ctx context.Context, client *http.Client, key string) (*SecretInfo, error) {
	user, err := fetchCurrentUser(ctx, client, key)
	if err != nil {
		return nil, err
	}
	secretInfo := &SecretInfo{User: *user}

	org, ok, err := fetchOrganization(ctx, client, key)
	if err != nil {
		return nil, err
	}
	if ok {
		secretInfo.Organization = org
	}

	keys, listed, err := fetchAPIKeys(ctx, client, key)
	if err != nil {
		return nil, err
	}
	if !listed {
		// Only service accounts without API key management permission are
		// denied the listing, and team keys are the only such keys.
		secretInfo.Category = categoryTeam
		return secretInfo, nil
	}

	prefix, _, _ := strings.Cut(key, ".")
	for i := range keys {
		if keys[i].Prefix == prefix {
			secretInfo.Key = &keys[i]
			continue
		}
		secretInfo.OtherKeys = append(secretInfo.OtherKeys, keys[i])
	}
	secretInfo.Category = categorize(secretInfo.Key, user)

	return secretInfo, nil
}

func categorize(key *apiKeyInfo, user *userResponse) string {
	if key == nil {
		// Service accounts have no email, so a key that can list keys but is
		// missing from the listing is personal only if its user has one.
		if user.Email != nil {
			return categoryPersonal
		}
		return categoryUnknown
	}

	switch key.Type {
	case keyTypePersonal:
		return categoryPersonal
	case keyTypeManageAPIKeys:
		return categoryOrganization
	case keyTypeManageAll, keyTypeInvoke, keyTypeExportMetrics, keyTypeGrid:
		return categoryTeam
	default:
		return categoryUnknown
	}
}

func secretInfoToAnalyzerResult(info *SecretInfo) *analyzers.AnalyzerResult {
	if info == nil {
		return nil
	}

	metadata := map[string]any{
		"Valid_Key":      true,
		"key_category":   info.Category,
		"user_id":        info.User.UserID,
		"user_name":      info.User.Name,
		"workspace_name": info.User.WorkspaceName,
	}
	if info.User.Email != nil {
		metadata["email"] = *info.User.Email
	}
	if info.Key != nil {
		for k, v := range map[string]string{
			"key_type":     info.Key.Type,
			"key_name":     info.Key.Name,
			"team_name":    info.Key.TeamName,
			"created_at":   info.Key.CreatedAt,
			"last_used_at": info.Key.LastUsedAt,
		} {
			if v != "" {
				metadata[k] = v
			}
		}
	}

	result := analyzers.AnalyzerResult{
		AnalyzerType: analyzers.AnalyzerTypeBaseten,
		Metadata:     metadata,
	}

	org := organizationResource(info)
	if info.Organization != nil {
		metadata["org_id"] = info.Organization.OrgID
	}

	if info.Key != nil {
		if permission, ok := keyTypePermissions[info.Key.Type]; ok {
			result.Bindings = append(result.Bindings, keyBindings(info.Key, &org, permission)...)
		}
	}

	if info.Category == categoryOrganization {
		for _, k := range info.OtherKeys {
			keyMetadata := map[string]any{"type": k.Type}
			if k.Name != "" {
				keyMetadata["name"] = k.Name
			}
			if k.TeamName != "" {
				keyMetadata["team_name"] = k.TeamName
			}
			if k.Owner != nil {
				keyMetadata["owner_email"] = k.Owner.Email
			}
			result.Bindings = append(result.Bindings, analyzers.Binding{
				Resource: analyzers.Resource{
					Name:               k.Prefix,
					FullyQualifiedName: org.FullyQualifiedName + "/api_key/" + k.Prefix,
					Type:               resourceTypeAPIKey,
					Metadata:           keyMetadata,
					Parent:             &org,
				},
				Permission: analyzers.Permission{Value: PermissionStrings[ManageApiKeys]},
			})
		}
	}

	return &result
}

// organizationResource identifies the workspace by its org ID when the key
// may read it, and by the workspace name otherwise.
func organizationResource(info *SecretInfo) analyzers.Resource {
	if info.Organization != nil {
		return analyzers.Resource{
			Name:               info.Organization.Name,
			FullyQualifiedName: "baseten.co/organization/" + info.Organization.OrgID,
			Type:               resourceTypeOrganization,
		}
	}
	return analyzers.Resource{
		Name:               info.User.WorkspaceName,
		FullyQualifiedName: "baseten.co/organization/" + info.User.WorkspaceName,
		Type:               resourceTypeOrganization,
	}
}

// keyBindings grants the key's permission on the models it is scoped to, or
// otherwise on its team, or otherwise on the whole organization.
func keyBindings(key *apiKeyInfo, org *analyzers.Resource, permission Permission) []analyzers.Binding {
	parent := org
	if key.TeamName != "" {
		parent = &analyzers.Resource{
			Name:               key.TeamName,
			FullyQualifiedName: org.FullyQualifiedName + "/team/" + key.TeamName,
			Type:               resourceTypeTeam,
			Parent:             org,
		}
	}

	if len(key.ModelIDs) == 0 {
		return []analyzers.Binding{{
			Resource:   *parent,
			Permission: analyzers.Permission{Value: PermissionStrings[permission]},
		}}
	}

	bindings := make([]analyzers.Binding, 0, len(key.ModelIDs))
	for _, id := range key.ModelIDs {
		bindings = append(bindings, analyzers.Binding{
			Resource: analyzers.Resource{
				Name:               id,
				FullyQualifiedName: parent.FullyQualifiedName + "/model/" + id,
				Type:               resourceTypeModel,
				Parent:             parent,
			},
			Permission: analyzers.Permission{Value: PermissionStrings[permission]},
		})
	}
	return bindings
}

func printKeyInfo(info *SecretInfo) {
	color.Yellow("[i] Key Information:")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Category", "Type", "Name", "Team", "User", "Workspace"})

	keyType, keyName, teamName := "unknown (key cannot list API keys)", "", ""
	if info.Key != nil {
		keyType, keyName, teamName = info.Key.Type, info.Key.Name, info.Key.TeamName
	}
	userName := info.User.Name
	if info.User.Email != nil {
		userName += " <" + *info.User.Email + ">"
	}
	t.AppendRow(table.Row{
		color.GreenString(info.Category),
		color.GreenString(keyType),
		color.GreenString(keyName),
		color.GreenString(teamName),
		color.GreenString(userName),
		color.GreenString(info.User.WorkspaceName),
	})
	t.Render()
}

func printAPIKeys(keys []apiKeyInfo) {
	color.Green("\n[i] Manageable API Keys:")
	if len(keys) == 0 {
		color.Yellow("None")
		return
	}

	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Prefix", "Name", "Type", "Team", "Last Used"})
	for _, k := range keys {
		t.AppendRow(table.Row{
			color.GreenString(k.Prefix),
			color.GreenString(k.Name),
			color.GreenString(k.Type),
			color.GreenString(k.TeamName),
			color.GreenString(k.LastUsedAt),
		})
	}
	t.Render()
}
