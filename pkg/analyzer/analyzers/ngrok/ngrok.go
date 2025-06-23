//go:generate generate_permissions permissions.yaml permissions.go ngrok
package ngrok

import (
	"errors"
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/v6/table"

	_ "embed"

	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

var _ analyzers.Analyzer = (*Analyzer)(nil)

type Analyzer struct {
	Cfg *config.Config
}

type AccountType string

const (
	AccountFree AccountType = "Free"
	AccountPaid AccountType = "Paid"
)

func (a Analyzer) Type() analyzers.AnalyzerType {
	return analyzers.AnalyzerTypeNgrok
}

func (a Analyzer) Analyze(_ context.Context, credInfo map[string]string) (*analyzers.AnalyzerResult, error) {
	key, exist := credInfo["key"]
	if !exist {
		return nil, errors.New("key not found in credentials info")
	}

	info, err := AnalyzePermissions(a.Cfg, key)
	if err != nil {
		return nil, err
	}

	return secretInfoToAnalyzerResult(info), nil
}

func AnalyzeAndPrintPermissions(cfg *config.Config, key string) {
	info, err := AnalyzePermissions(cfg, key)
	if err != nil {
		color.Red("[x] Invalid Ngrok Key\n")
		color.Red("[x] Error : %s", err.Error())
		return
	}

	if info == nil {
		color.Red("[x] Error : %s", "No information found")
		return
	}

	color.Green("[i] Valid Ngrok API Key\n")
	printAccountAndPermissions(info)
}

func AnalyzePermissions(cfg *config.Config, key string) (*secretInfo, error) {
	// Ngrok API keys provide full access to all resources depending on the account type
	// Free accounts have access to a limited set of resources.
	client := analyzers.NewAnalyzeClient(cfg)
	secretInfo := &secretInfo{}

	if err := determineAccountType(client, secretInfo, key); err != nil {
		return nil, err
	}

	if err := populateAllResources(client, secretInfo, key); err != nil {
		return nil, err
	}

	return secretInfo, nil
}

func secretInfoToAnalyzerResult(info *secretInfo) *analyzers.AnalyzerResult {
	if info == nil {
		return nil
	}

	bindings := []analyzers.Binding{}
	fullAccessPermission := analyzers.Permission{
		Value: PermissionStrings[FullAccess],
	}

	for _, endpoint := range info.Endpoints {
		bindings = append(bindings, analyzers.Binding{
			Resource:   createEndpointResource(endpoint),
			Permission: fullAccessPermission,
		})
	}

	for _, domain := range info.Domains {
		bindings = append(bindings, analyzers.Binding{
			Resource:   createDomainResource(domain),
			Permission: fullAccessPermission,
		})
	}

	for _, apiKey := range info.APIKeys {
		bindings = append(bindings, analyzers.Binding{
			Resource:   createAPIKeyResource(apiKey),
			Permission: fullAccessPermission,
		})
	}

	for _, authtoken := range info.Authtokens {
		bindings = append(bindings, analyzers.Binding{
			Resource:   createAuthtokenResource(authtoken),
			Permission: fullAccessPermission,
		})
	}

	for _, sshCredential := range info.SSHCredentials {
		bindings = append(bindings, analyzers.Binding{
			Resource:   createSSHKeyResource(sshCredential),
			Permission: fullAccessPermission,
		})
	}

	for _, botUser := range info.BotUsers {
		bindings = append(bindings, analyzers.Binding{
			Resource:   createBotUserResource(botUser),
			Permission: fullAccessPermission,
		})
	}

	for _, user := range info.Users {
		bindings = append(bindings, analyzers.Binding{
			Resource:   createUserResource(user),
			Permission: fullAccessPermission,
		})
	}

	result := analyzers.AnalyzerResult{
		AnalyzerType: analyzers.AnalyzerTypeNgrok,
		Metadata:     nil,
		Bindings:     bindings,
		UnboundedResources: []analyzers.Resource{{
			Name:               "Account Plan",
			FullyQualifiedName: "account_plan/" + string(info.AccountType),
			Type:               "account_plan",
		}},
	}
	return &result
}

func printAccountAndPermissions(info *secretInfo) {
	accountIsFree := info.AccountType != AccountPaid
	color.Yellow("[i] Account Type: %s", info.AccountType)

	color.Yellow("\n[i] Permissions:")
	t1 := table.NewWriter()
	t1.AppendHeader(table.Row{"Resource", "Access Level"})

	// Printing the access level to Ngrok resources
	for _, resource := range ngrokResources {
		accessLevel := "Full Access"
		if resource.IsPaidFeature && accountIsFree {
			accessLevel = "None"
		}
		t1.AppendRow(table.Row{
			color.GreenString(resource.Name),
			color.GreenString(accessLevel),
		})
		t1.AppendSeparator()
	}

	t1.SetOutputMirror(os.Stdout)
	t1.Render()

	color.Yellow("\n[i] Resources:")

	t2 := table.NewWriter()
	t2.SetTitle("User IDs")
	t2.AppendHeader(table.Row{"ID"})

	for _, user := range info.Users {
		t2.AppendRow(table.Row{
			color.GreenString(user.ID),
		})
	}

	t2.SetOutputMirror(os.Stdout)
	t2.Render()

	t3 := table.NewWriter()
	t3.SetTitle("Endpoints")
	t3.AppendHeader(table.Row{"ID", "Region", "Public URL", "Type", "Created At", "Updated At"})
	for _, endpoint := range info.Endpoints {
		t3.AppendRow(table.Row{
			color.GreenString(endpoint.ID),
			color.GreenString(endpoint.Region),
			color.GreenString(endpoint.PublicURL),
			color.GreenString(endpoint.Type),
			color.GreenString(endpoint.CreatedAt),
			color.GreenString(endpoint.UpdatedAt),
		})
	}

	t3.SetOutputMirror(os.Stdout)
	t3.Render()

	t4 := table.NewWriter()
	t4.SetTitle("Domains")
	t4.AppendHeader(table.Row{"ID", "Domain", "URI", "Created At"})
	for _, domain := range info.Domains {
		t4.AppendRow(table.Row{
			color.GreenString(domain.ID),
			color.GreenString(domain.Domain),
			color.GreenString(domain.URI),
			color.GreenString(domain.CreatedAt),
		})
	}

	t4.SetOutputMirror(os.Stdout)
	t4.Render()

	t5 := table.NewWriter()
	t5.SetTitle("API Keys")
	t5.AppendHeader(table.Row{"ID", "Description", "Owner ID", "Created At"})
	for _, key := range info.APIKeys {
		t5.AppendRow(table.Row{
			color.GreenString(key.ID),
			color.GreenString(key.Description),
			color.GreenString(key.OwnerID),
			color.GreenString(key.CreatedAt),
		})
	}

	t5.SetOutputMirror(os.Stdout)
	t5.Render()

	t6 := table.NewWriter()
	t6.SetTitle("Authtokens")
	t6.AppendHeader(table.Row{"ID", "Description", "Owner ID", "Created At"})
	for _, token := range info.Authtokens {
		t6.AppendRow(table.Row{
			color.GreenString(token.ID),
			color.GreenString(token.Description),
			color.GreenString(token.OwnerID),
			color.GreenString(token.CreatedAt),
		})
	}

	t6.SetOutputMirror(os.Stdout)
	t6.Render()

	t7 := table.NewWriter()
	t7.SetTitle("SSH Credentials")
	t7.AppendHeader(table.Row{"ID", "Description", "Owner ID", "Created At"})
	for _, key := range info.SSHCredentials {
		t7.AppendRow(table.Row{
			color.GreenString(key.ID),
			color.GreenString(key.Description),
			color.GreenString(key.OwnerID),
			color.GreenString(key.CreatedAt),
		})
	}

	t7.SetOutputMirror(os.Stdout)
	t7.Render()

	t8 := table.NewWriter()
	t8.SetTitle("Bot Users")
	t8.AppendHeader(table.Row{"ID", "Name", "Is Active", "Created At"})
	for _, endpoint := range info.BotUsers {
		isActive := "No"
		if endpoint.Active {
			isActive = "Yes"
		}
		t8.AppendRow(table.Row{
			color.GreenString(endpoint.ID),
			color.GreenString(endpoint.Name),
			color.GreenString(isActive),
			color.GreenString(endpoint.CreatedAt),
		})
	}

	t8.SetOutputMirror(os.Stdout)
	t8.Render()

	fmt.Printf("%s: https://www.ngrok.com/developers/documentation\n\n", color.GreenString("Ref"))
}
