//go:generate generate_permissions permissions.yaml permissions.go mailgun
package mailgun

import (
	"errors"
	"os"
	"strconv"

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

type SecretInfo struct {
	ID        string // key id
	UserName  string
	Type      string // type of key
	Role      string // key role
	ExpiresAt string // key expiry time if any
	Domains   []Domain
}

func (Analyzer) Type() analyzers.AnalyzerType { return analyzers.AnalyzerTypeMailgun }

func (a Analyzer) Analyze(_ context.Context, credInfo map[string]string) (*analyzers.AnalyzerResult, error) {
	key, ok := credInfo["key"]
	if !ok {
		return nil, analyzers.NewAnalysisError(
			"Mailgun", "validate_credentials", "config", "", errors.New("key not found in credentialInfo"),
		)
	}

	info, err := AnalyzePermissions(a.Cfg, key)
	if err != nil {
		return nil, analyzers.NewAnalysisError(
			"Mailgun", "analyze_permissions", "API", "", err,
		)
	}

	return secretInfoToAnalyzerResult(info), nil
}

func secretInfoToAnalyzerResult(info *SecretInfo) *analyzers.AnalyzerResult {
	if info == nil {
		return nil
	}
	result := analyzers.AnalyzerResult{
		AnalyzerType: analyzers.AnalyzerTypeMailgun,
		Bindings:     make([]analyzers.Binding, len(info.Domains)),
	}

	for idx, domain := range info.Domains {
		result.Bindings[idx] = analyzers.Binding{
			Resource: analyzers.Resource{
				Name:               domain.URL,
				FullyQualifiedName: "mailgun/" + domain.ID + "/" + domain.URL,
				Type:               "domain",
				Metadata: map[string]any{
					"created_at":  domain.CreatedAt,
					"type":        domain.Type,
					"state":       domain.State,
					"is_disabled": domain.IsDisabled,
				},
			},

			Permission: analyzers.Permission{
				Value: PermissionStrings[FullAccess],
			},
		}
	}
	return &result
}

func AnalyzeAndPrintPermissions(cfg *config.Config, apiKey string) {
	info, err := AnalyzePermissions(cfg, apiKey)
	if err != nil {
		color.Red("[x] %s", err.Error())
		return
	}

	color.Green("[i] Valid Mailgun API key\n\n")
	printKeyInfo(info)
	printDomains(info.Domains)
	color.Yellow("[i] Permissions: Full Access\n\n")
}

func AnalyzePermissions(cfg *config.Config, apiKey string) (*SecretInfo, error) {
	var secretInfo SecretInfo

	var client = analyzers.NewAnalyzeClient(cfg)

	if err := getDomains(client, apiKey, &secretInfo); err != nil {
		return &secretInfo, err
	}

	if err := getKeys(client, apiKey, &secretInfo); err != nil {
		return &secretInfo, err
	}

	return &secretInfo, nil
}

func printKeyInfo(info *SecretInfo) {
	if info.ID == "" {
		color.Red("[i] Key information not found")
		return
	}

	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Key ID", "UserName/Requester", "Key Type", "Expires At", "Role"})
	t.AppendRow(table.Row{info.ID, info.UserName, info.Type, info.ExpiresAt, info.Role})
	t.Render()
}
func printDomains(domains []Domain) {
	if len(domains) == 0 {
		color.Red("[i] No domains found")
		return
	}

	color.Yellow("[i] Found %d domain(s)", len(domains))

	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Domain", "Type", "State", "Created At", "Disabled"})

	for _, domain := range domains {
		var colorFunc func(format string, a ...interface{}) string
		switch {
		case domain.IsDisabled:
			colorFunc = color.RedString
		case domain.Type == "sandbox" || domain.State == "unverified":
			colorFunc = color.YellowString
		default:
			colorFunc = color.GreenString
		}

		t.AppendRow([]interface{}{
			colorFunc(domain.URL),
			colorFunc(domain.Type),
			colorFunc(domain.State),
			colorFunc(domain.CreatedAt),
			colorFunc(strconv.FormatBool(domain.IsDisabled)),
		})
	}

	t.Render()
}
