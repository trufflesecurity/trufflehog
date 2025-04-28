package netlify

import (
	"fmt"
	"os"

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

func (a Analyzer) Type() analyzers.AnalyzerType {
	return analyzers.AnalyzerTypeNetlify
}

func (a Analyzer) Analyze(_ context.Context, credInfo map[string]string) (*analyzers.AnalyzerResult, error) {
	_, exist := credInfo["key"]
	if !exist {
		return nil, fmt.Errorf("key not found in credential info")
	}

	return nil, nil
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

	color.Green("[!] Valid Fastly API key\n\n")

	printUserInfo(info.UserInfo)
	printTokenInfo(info.listResourceByType(Token))
	printResources(info.Resources)

	color.Yellow("\n[i] Expires: %s", "N/A (Refer to Token Information Table)")
}

func AnalyzePermissions(cfg *config.Config, key string) (*SecretInfo, error) {
	client := analyzers.NewAnalyzeClient(cfg)

	var secretInfo = &SecretInfo{}

	if err := captureUserInfo(client, key, secretInfo); err != nil {
		return nil, err
	}

	if err := captureTokens(client, key, secretInfo); err != nil {
		return nil, err
	}

	if err := captureResources(client, key, secretInfo); err != nil {
		return secretInfo, err
	}

	return secretInfo, nil
}

// cli print functions
func printUserInfo(user User) {
	color.Yellow("[i] User Information:")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Name", "Email", "Account ID", "Last Login At"})
	t.AppendRow(table.Row{color.GreenString(user.Name), color.GreenString(user.Email), color.GreenString(user.AccountID), color.GreenString(user.LastLogin)})

	t.Render()
}

func printTokenInfo(tokens []NetlifyResource) {
	color.Yellow("[i] Tokens Information:")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"ID", "Name", "Personal", "Expires At"})
	for _, token := range tokens {
		t.AppendRow(table.Row{color.GreenString(token.ID), color.GreenString(token.Name), color.GreenString(token.Metadata[tokenPersonal]), color.GreenString(token.Metadata[tokenExpiresAt])})
	}
	t.Render()
}

func printResources(resources []NetlifyResource) {
	color.Yellow("[i] Resources:")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Name", "Type"})
	for _, resource := range resources {
		// skip token type resource as we will print them separately
		if resource.Type == Token.String() {
			continue
		}

		t.AppendRow(table.Row{color.GreenString(resource.Name), color.GreenString(resource.Type)})
	}
	t.Render()
}
