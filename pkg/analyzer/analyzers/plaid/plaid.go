//go:generate generate_permissions permissions.yaml permissions.go plaid
package plaid

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
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

type Analyzer struct {
	Cfg *config.Config
}

func (a Analyzer) Type() analyzers.AnalyzerType {
	return analyzers.AnalyzerTypePlaid
}

func (a Analyzer) Analyze(_ context.Context, credInfo map[string]string) (*analyzers.AnalyzerResult, error) {
	secret, exist := credInfo["secret"]
	if !exist {
		return nil, errors.New("secret not found in credentials info")
	}
	clientID, exist := credInfo["id"]
	if !exist {
		return nil, errors.New("id not found in credentials info")
	}
	accessToken, exist := credInfo["token"]
	if !exist {
		return nil, errors.New("token not found in credentials info")
	}

	info, err := AnalyzePermissions(a.Cfg, secret, clientID, accessToken)
	if err != nil {
		return nil, err
	}

	return secretInfoToAnalyzerResult(info), nil
}

func AnalyzeAndPrintPermissions(cfg *config.Config, secret string, clientID string, accessToken string) {
	info, err := AnalyzePermissions(cfg, secret, clientID, accessToken)
	if err != nil {
		color.Red("[x] Invalid Plaid API key\n")
		color.Red("[x] Error : %s", err.Error())
		return
	}

	if info == nil {
		color.Red("[x] Error : %s", "No information found")
		return
	}

	color.Green("[i] Valid Plaid API Credentials\n")
	color.Yellow("[i] Environment: %s", info.Environment)
	if info.Environment == "sandbox" {
		color.Cyan("Credentials are for Sandbox environment. All resources found are simulated and not real data.\n")
	}
	printAccountsAndProducts(info)
}

func AnalyzePermissions(cfg *config.Config, secret string, clientId string, accessToken string) (*secretInfo, error) {
	environment := ""
	if strings.Contains(accessToken, "production") {
		environment = "production"
	}
	if strings.Contains(accessToken, "sandbox") {
		environment = "sandbox"
	}
	if environment == "" {
		return nil, errors.New("Environment could not be parsed from access token")
	}

	client := analyzers.NewAnalyzeClient(cfg)
	var secretInfo = &secretInfo{}
	secretInfo.Environment = environment
	resp, err := getPlaidAccounts(client, clientId, secret, accessToken, environment)
	if err != nil {
		return nil, err
	}
	secretInfo.Accounts = resp.Accounts
	secretInfo.Products = resp.Item.Products
	return secretInfo, nil
}

func getPlaidAccounts(client *http.Client, clientID string, secret string, accessToken string, environment string) (*accountsResponse, error) {
	body := map[string]interface{}{
		"client_id":    clientID,
		"secret":       secret,
		"access_token": accessToken,
	}
	url := "https://" + environment + ".plaid.com/accounts/get"
	jsonBody, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var accounts accountsResponse
	if err := json.NewDecoder(resp.Body).Decode(&accounts); err != nil {
		return nil, err
	}

	return &accounts, nil
}

func secretInfoToAnalyzerResult(info *secretInfo) *analyzers.AnalyzerResult {
	if info == nil {
		return nil
	}

	result := analyzers.AnalyzerResult{
		AnalyzerType:       analyzers.AnalyzerTypePlaid,
		Metadata:           nil,
		Bindings:           make([]analyzers.Binding, len(info.Products)),
		UnboundedResources: make([]analyzers.Resource, len(info.Accounts)),
	}
	resource := analyzers.Resource{
		Name:               "Plaid API Access Token",
		FullyQualifiedName: "Plaid API Access Token",
		Type:               "Access Token",
	}

	for idx, product := range info.Products {
		result.Bindings[idx] = analyzers.Binding{
			Resource: resource,
			Permission: analyzers.Permission{
				Value: product,
			},
		}
	}

	for idx, account := range info.Accounts {
		result.UnboundedResources[idx] = analyzers.Resource{
			Name:               account.Name,
			FullyQualifiedName: account.OfficialName,
			Type:               "account",
			Metadata: map[string]any{
				"accountID": account.AccountID,
			},
		}
	}

	return &result
}

func printAccountsAndProducts(info *secretInfo) {
	color.Yellow("[i] Accounts Info:")
	t1 := table.NewWriter()
	t1.SetOutputMirror(os.Stdout)
	t1.AppendHeader(table.Row{"ID", "Name", "Official Name", "Type", "Subtype"})
	for _, account := range info.Accounts {
		t1.AppendRow(table.Row{
			color.GreenString(account.AccountID),
			color.GreenString(account.Name),
			color.GreenString(account.OfficialName),
			color.GreenString(account.Type),
			color.GreenString(account.Subtype),
		})
		t1.AppendSeparator()
	}
	t1.SetOutputMirror(os.Stdout)
	t1.Render()

	color.Yellow("\n[i] Products:")
	t2 := table.NewWriter()
	t2.AppendHeader(table.Row{"Product Name", "Status", "Capabilities"})

	// Products are mapped as permissions
	for perm, str := range PermissionStrings {
		product, ok := permissionToProduct[perm]
		if !ok {
			continue
		}

		productCell := color.GreenString(product.Name)
		productDescCell := color.GreenString(product.Description)
		status := "Denied"

		for _, product := range info.Products {
			if product == str {
				status = "Granted"
			}
		}

		t2.AppendRow(table.Row{productCell, color.GreenString(status), productDescCell})
		t2.AppendSeparator()
	}

	t2.SetOutputMirror(os.Stdout)
	t2.Render()
	fmt.Printf("%s: https://plaid.com/docs/api/\n\n", color.GreenString("Ref"))
}
