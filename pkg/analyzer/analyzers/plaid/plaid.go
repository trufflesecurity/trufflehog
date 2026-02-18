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
		return nil, analyzers.NewAnalysisError("Plaid", "validate_credentials", "config", "", errors.New("secret not found in credentials info"))
	}
	clientID, exist := credInfo["id"]
	if !exist {
		return nil, analyzers.NewAnalysisError("Plaid", "validate_credentials", "config", "", errors.New("id not found in credentials info"))
	}
	accessToken, exist := credInfo["token"]
	if !exist {
		return nil, analyzers.NewAnalysisError("Plaid", "validate_credentials", "config", "", errors.New("token not found in credentials info"))
	}

	info, err := AnalyzePermissions(a.Cfg, secret, clientID, accessToken)
	if err != nil {
		return nil, analyzers.NewAnalysisError("Plaid", "analyze_permissions", "API", "", err)
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
	color.Yellow("\n[i] Environment: %s", info.Environment)
	if info.Environment == "sandbox" {
		color.Cyan("Credentials are for Sandbox environment. All resources found are simulated and not real data.\n")
	}
	printAccountsAndProducts(info)
}

func AnalyzePermissions(cfg *config.Config, secret string, clientId string, accessToken string) (*secretInfo, error) {
	environment := "sandbox"
	if strings.Contains(accessToken, "production") {
		environment = "production"
	}

	// Plaid API uses POST requests for all requests, so we need to use an unrestricted client
	client := analyzers.NewAnalyzeClientUnrestricted(cfg)
	var secretInfo = &secretInfo{}
	secretInfo.Environment = environment
	resp, err := getPlaidAccounts(client, clientId, secret, accessToken, environment)
	if err != nil {
		return nil, err
	}
	secretInfo.Item = resp.Item
	secretInfo.Accounts = resp.Accounts
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

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("received non-OK HTTP status: %d", resp.StatusCode)
	}

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

	itemID := info.Item.ItemID
	userProducts := info.Item.Products
	userAccounts := info.Accounts

	result := analyzers.AnalyzerResult{
		AnalyzerType:       analyzers.AnalyzerTypePlaid,
		Metadata:           nil,
		Bindings:           make([]analyzers.Binding, len(userProducts)),
		UnboundedResources: make([]analyzers.Resource, len(userAccounts)),
	}

	for idx, productName := range userProducts {
		product, ok := GetProductByName(productName)
		if !ok {
			continue
		}
		result.Bindings[idx] = analyzers.Binding{
			Resource: analyzers.Resource{
				Name:               product.DisplayName,
				FullyQualifiedName: itemID + "/product/" + product.Name,
				Type:               "product",
				Metadata: map[string]any{
					"productDesc": product.Description,
				},
			},
			Permission: analyzers.Permission{
				Value: PermissionStrings[product.PermissionLevel],
			},
		}
	}

	for idx, account := range info.Accounts {
		result.UnboundedResources[idx] = analyzers.Resource{
			Name:               account.Name,
			FullyQualifiedName: account.AccountID,
			Type:               "account",
			Metadata: map[string]any{
				"officialName": account.OfficialName,
			},
		}
	}

	return &result
}

func printAccountsAndProducts(info *secretInfo) {
	userProducts := info.Item.Products
	userAccounts := info.Accounts

	color.Yellow("\n[i] Item ID: %s", info.Item.ItemID)

	color.Yellow("\n[i] Accounts Info:")
	t1 := table.NewWriter()
	t1.SetOutputMirror(os.Stdout)
	t1.AppendHeader(table.Row{"ID", "Name", "Official Name", "Type", "Subtype"})
	for _, account := range userAccounts {
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
	t2.AppendHeader(table.Row{"Product Name", "Access Level", "Capabilities"})

	for _, product := range plaidProducts {
		productCell := color.GreenString(product.DisplayName)
		productDescCell := color.GreenString(product.Description)
		productPermissionCell := color.GreenString("Denied")

		for _, productName := range userProducts {
			if productName == product.Name {
				permissionLevel := PermissionStrings[product.PermissionLevel]
				productPermissionCell = "Granted" // If permission level is not defined, default to "Granted"
				if len(permissionLevel) > 0 {
					// Capitalize the perssion level string
					capitalizedLevel := strings.ToUpper(string(permissionLevel[0])) + strings.ToLower(permissionLevel[1:])
					productPermissionCell = color.GreenString(capitalizedLevel)
				}
				break
			}
		}

		t2.AppendRow(table.Row{productCell, productPermissionCell, productDescCell})
		t2.AppendSeparator()
	}

	t2.SetOutputMirror(os.Stdout)
	t2.Render()
	fmt.Printf("%s: https://plaid.com/docs/api/\n\n", color.GreenString("Ref"))
}
