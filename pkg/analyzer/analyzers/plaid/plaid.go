//go:generate generate_permissions permissions.yaml permissions.go plaid
package plaid

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
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
	return analyzers.AnalyzerTypePlaid
}

var permissionToProduct = map[Permission]string{
	Assets:                "Assets",
	Auth:                  "Auth",
	Balance:               "Balance",
	BalancePlus:           "Balance Plus",
	Beacon:                "Beacon",
	CraBaseReport:         "CRA Base Report",
	CraIncomeInsights:     "CRA Income Insights",
	CraPartnerInsights:    "CRA Partner Insights",
	CraNetworkInsights:    "CRA Network Insights",
	CraCashflowInsights:   "CRA Cashflow Insights",
	CreditDetails:         "Credit Details",
	Employment:            "Employment",
	Identity:              "Identity",
	IdentityMatch:         "Identity Match",
	IdentityVerification:  "Identity Verification",
	Income:                "Income",
	IncomeVerification:    "Income Verification",
	Investments:           "Investments",
	InvestmentsAuth:       "Investments Auth",
	Layer:                 "Layer",
	Liabilities:           "Liabilities",
	PayByBank:             "Pay By Bank",
	PaymentInitiation:     "Payment Initiation",
	ProcessorPayments:     "Processor Payments",
	ProcessorIdentity:     "Processor Identity",
	Profile:               "Profile",
	RecurringTransactions: "Recurring Transactions",
	Signal:                "Signal",
	StandingOrders:        "Standing Orders",
	Statements:            "Statements",
	Transactions:          "Transactions",
	TransactionsRefresh:   "Transactions Refresh",
	Transfer:              "Transfer",
}

func (a Analyzer) Analyze(_ context.Context, credInfo map[string]string) (*analyzers.AnalyzerResult, error) {
	secret, exist := credInfo["secret"]
	if !exist {
		return nil, errors.New("secret not found in credentials info")
	}
	clientID, exist := credInfo["clientID"]
	if !exist {
		return nil, errors.New("clientID not found in credentials info")
	}
	accessToken, exist := credInfo["accessToken"]
	if !exist {
		return nil, errors.New("key not found in credentials info")
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
		// just print the error in cli and continue as a partial success
		color.Red("[x] Invalid Anthropic API key\n")
		color.Red("[x] Error : %s", err.Error())
		return
	}

	if info == nil {
		color.Red("[x] Error : %s", "No information found")
		return
	}

	color.Green("[i] Valid Plaid API Credentials\n")

	// if len(info.plaidResources) > 0 {
	// 	printplaidResources(info.plaidResources)
	// }

	color.Yellow("\n[!] Expires: Never")
}

func AnalyzePermissions(cfg *config.Config, clientId string, secret string, accessToken string) (*secretInfo, error) {
	// create a HTTP client
	client := analyzers.NewAnalyzeClient(cfg)
	var secretInfo = &secretInfo{}
	resp, err := getPlaidAccounts(client, clientId, secret, accessToken)
	if err != nil {
		return nil, err
	}
	secretInfo.Accounts = resp.Accounts
	secretInfo.Products = resp.Item.Products
	return secretInfo, nil
}

func getPlaidAccounts(client *http.Client, clientID string, secret string, accessToken string) (*accountsResponse, error) {
	body := map[string]interface{}{
		"client_id":    clientID,
		"secret":       secret,
		"access_token": accessToken,
	}
	jsonBody, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, "https://sandbox.plaid.com/accounts/get", bytes.NewBuffer(jsonBody))
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

	result.Bindings = analyzers.BindAllPermissions(userResource, permissions...)
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
	}
	t1.SetOutputMirror(os.Stdout)
	t1.Render()

	color.Yellow("\n[i] Products:")
	t2 := table.NewWriter()
	t2.AppendHeader(table.Row{"Product Name", "Status"})
	// Products are mapped as permissions
	for perm, str := range PermissionStrings {
		productCell := color.GreenString(permissionToProduct[perm])
		status := "Denied"
		for _, product := range info.Products {
			if product == str {
				status = "Granted"
			}
		}

		t2.AppendRow(table.Row{productCell, color.GreenString(status)})
	}

	t2.SetOutputMirror(os.Stdout)
	t2.Render()
	fmt.Printf("%s: https://plaid.com/docs/api/\n\n", color.GreenString("Ref"))
}
