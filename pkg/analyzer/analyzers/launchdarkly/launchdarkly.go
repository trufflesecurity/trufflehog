package launchdarkly

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
	return analyzers.AnalyzerTypeLaunchDarkly
}

func (a Analyzer) Analyze(_ context.Context, credInfo map[string]string) (*analyzers.AnalyzerResult, error) {
	return nil, nil
}

func AnalyzeAndPrintPermissions(cfg *config.Config, token string) {
	info, err := AnalyzePermissions(cfg, token)
	if err != nil {
		// just print the error in cli and continue as a partial success
		color.Red("[x] Error : %s", err.Error())
	}

	if info == nil {
		color.Red("[x] Error : %s", "No information found")
		return
	}

	color.Green("[i] Valid LaunchDarkly Token\n")
	printCallerIdentity(info.CallerIdentity)

	color.Yellow("\n[!] Expires: Never")
}

// AnalyzePermissions will collect all the scopes assigned to token along with resource it can access
func AnalyzePermissions(cfg *config.Config, token string) (*SecretInfo, error) {
	// create the http client
	client := analyzers.NewAnalyzeClient(cfg)

	var secretInfo = &SecretInfo{}

	// get caller identity
	callerIdentity, err := fetchCallerDetails(client, token)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch caller identity: %v", err)
	}

	if callerIdentity != nil {
		secretInfo.CallerIdentity = *callerIdentity
	}

	return secretInfo, nil
}

func printCallerIdentity(caller CallerIdentity) {
	// print caller information
	color.Green("\n[i] Caller:")
	callerTable := table.NewWriter()
	callerTable.SetOutputMirror(os.Stdout)
	callerTable.AppendHeader(table.Row{"Account ID", "Member ID", "Name", "Email", "Role"})
	callerTable.AppendRow(table.Row{color.GreenString(caller.AccountID), color.GreenString(caller.MemberID),
		color.GreenString(caller.Name), color.GreenString(caller.Email), color.GreenString(caller.Role)})

	callerTable.Render()

	// print token information
	color.Green("\n[i] Token")
	tokenTable := table.NewWriter()
	tokenTable.SetOutputMirror(os.Stdout)
	tokenTable.AppendHeader(table.Row{"ID", "Name", "Role", "Is Service Token", "Default API Version"})
	tokenTable.AppendRow(table.Row{color.GreenString(caller.Token.ID), color.GreenString(caller.Token.Name), color.GreenString(caller.Token.Role),
		color.GreenString(fmt.Sprintf("%t", caller.Token.IsServiceToken)), color.GreenString(fmt.Sprintf("%d", caller.Token.APIVersion))})

	tokenTable.Render()
}
