package databricks

import (
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
	return analyzers.AnalyzerTypeDataBricks
}

func (a Analyzer) Analyze(_ context.Context, credInfo map[string]string) (*analyzers.AnalyzerResult, error) {
	return nil, nil
}

func AnalyzeAndPrintPermissions(cfg *config.Config, domain, token string) {
	info, err := AnalyzePermissions(cfg, domain, token)
	if err != nil {
		// just print the error in cli and continue as a partial success
		color.Red("[x] Error : %s", err.Error())
	}

	if info == nil {
		color.Red("[x] Error : %s", "No information found")
		return
	}

	color.Green("[!] Valid DataBricks Access Token\n\n")

	printUserInfo(info.UserInfo)
	printTokenInfo(info.Tokens)

	color.Yellow("\n[i] Expires: %s", "N/A (Refer to Token Information Table)")
}

func AnalyzePermissions(cfg *config.Config, domain, key string) (*SecretInfo, error) {
	client := analyzers.NewAnalyzeClient(cfg)

	var secretInfo = &SecretInfo{}

	if err := captureUserInfo(client, domain, key, secretInfo); err != nil {
		return nil, err
	}

	if err := captureTokensInfo(client, domain, key, secretInfo); err != nil {
		return nil, err
	}

	return secretInfo, nil
}

// cli print functions
func printUserInfo(user User) {
	color.Yellow("[i] User Information:")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"ID", "UserName", "Primary Email"})
	t.AppendRow(table.Row{color.GreenString(user.ID), color.GreenString(user.UserName), color.GreenString(user.PrimaryEmail)})

	t.Render()
}

func printTokenInfo(tokens []Token) {
	color.Yellow("[i] Tokens Information:")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"ID", "Name", "Expiry Time", "Created By", "Last Used At"})
	for _, token := range tokens {
		t.AppendRow(table.Row{color.GreenString(token.ID), color.GreenString(token.Name),
			color.GreenString(token.ExpiryTime), color.GreenString(token.CreatedBy), color.GreenString(token.LastUsedDay)})
	}
	t.Render()
}
