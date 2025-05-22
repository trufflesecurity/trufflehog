//go:generate generate_permissions permissions.yaml permissions.go coinbase
package coinbase

import (
	_ "embed"
	"errors"
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
	return analyzers.AnalyzerTypeCoinbase
}

func (a Analyzer) Analyze(_ context.Context, credInfo map[string]string) (*analyzers.AnalyzerResult, error) {
	keyName, exist := credInfo["keyName"]
	if !exist {
		return nil, errors.New("keyName not found in credentials info")
	}
	key, exist := credInfo["key"]
	if !exist {
		return nil, errors.New("key not found in credentials info")
	}

	info, err := AnalyzePermissions(a.Cfg, keyName, key)
	if err != nil {
		return nil, err
	}

	return secretInfoToAnalyzerResult(info), nil
}

func AnalyzeAndPrintPermissions(cfg *config.Config, keyName, key string) {
	info, err := AnalyzePermissions(cfg, keyName, key)
	if err != nil {
		color.Red("[x] Invalid Coinbase key name or key\n")
		color.Red("[x] Error : %s", err.Error())
		return
	}

	if info == nil {
		color.Red("[x] Error : %s", "No information found")
		return
	}

	color.Green("[i] Valid Coinbase API Credentials\n")
	resourceConfig, err := readInResources()
	if err != nil {
		color.Red("[x] Error : %s", "Could not read in resources from json")
		return
	}
	printResourcesAndPermissions(info, resourceConfig)
}

func AnalyzePermissions(cfg *config.Config, keyName, key string) (*secretInfo, error) {
	client := analyzers.NewAnalyzeClient(cfg)
	secretInfo := &secretInfo{}
	if err := testAllPermissions(client, secretInfo, keyName, key); err != nil {
		return nil, err
	}
	if err := populateResources(client, secretInfo, keyName, key); err != nil {
		return nil, err
	}

	return secretInfo, nil
}

func secretInfoToAnalyzerResult(info *secretInfo) *analyzers.AnalyzerResult {
	if info == nil {
		return nil
	}

	bindings := []analyzers.Binding{}

	for _, account := range info.Accounts {
		resource := createAccountResource(account)
		bindings = append(bindings, createBindings(info, &resource)...)
	}

	for _, portfolio := range info.Portfolios {
		resource := createPortfolioResource(portfolio)
		bindings = append(bindings, createBindings(info, &resource)...)
	}

	for _, paymentMethod := range info.PaymentMethods {
		resource := createPaymentMethodResource(paymentMethod)
		bindings = append(bindings, createBindings(info, &resource)...)
	}

	for _, order := range info.Orders {
		resource := createOrderResource(order)
		bindings = append(bindings, createBindings(info, &resource)...)
	}

	for _, wallet := range info.Wallets {
		resource := createWalletResource(wallet)
		bindings = append(bindings, createBindings(info, &resource)...)
	}

	for _, address := range info.Addresses {
		resource := createAddressResource(address)
		bindings = append(bindings, createBindings(info, &resource)...)
	}

	result := analyzers.AnalyzerResult{
		AnalyzerType: analyzers.AnalyzerTypeCoinbase,
		Metadata:     nil,
		Bindings:     bindings,
	}
	return &result
}

func printResourcesAndPermissions(info *secretInfo, resourceConfig *coinbaseAPIResourceConfig) {
	printPermissionsTable(info)
	printAccessLevelTable(info, resourceConfig)
	printResources(info)

	fmt.Printf("%s: https://docs.cdp.coinbase.com/coinbase-app/docs\n\n", color.GreenString("Ref"))
}

func printPermissionsTable(info *secretInfo) {
	color.Yellow("\n[i] Permissions:")
	permissionsTable := table.NewWriter()
	permissionsTable.AppendHeader(table.Row{"Permission Name", "Has Permission"})

	for _, str := range PermissionStrings {
		hasPermission := info.hasPermission(str)

		hasPermissionText := "No"
		if hasPermission {
			hasPermissionText = "Yes"
		}

		permissionsTable.AppendRow(table.Row{
			color.GreenString(str),
			color.GreenString(hasPermissionText),
		})
		permissionsTable.AppendSeparator()
	}

	permissionsTable.SetOutputMirror(os.Stdout)
	permissionsTable.Render()
}

func printAccessLevelTable(info *secretInfo, resourceConfig *coinbaseAPIResourceConfig) {
	color.Yellow("\n[i] Resource Access Levels:")
	accessLevelTableHeader := table.Row{"Resource", "Action", "Can Perform"}

	for _, api := range resourceConfig.APIs {
		accessLevelTable := table.NewWriter()
		accessLevelTable.SetTitle(api.APIName)
		accessLevelTable.AppendHeader(accessLevelTableHeader)
		for _, resource := range api.Resources {
			for idx, action := range resource.Actions {
				resourceText := ""
				canPerformText := "No"

				if idx == 0 {
					resourceText = resource.Name
				}

				if info.hasPermission(action.RequiredPermission) {
					canPerformText = "Yes"
				}

				accessLevelTable.AppendRow(table.Row{
					color.GreenString(resourceText),
					color.GreenString(action.Name),
					color.GreenString(canPerformText),
				})
			}
			accessLevelTable.AppendSeparator()
		}
		accessLevelTable.SetOutputMirror(os.Stdout)
		accessLevelTable.Render()
	}
}

func printResources(info *secretInfo) {
	printAccounts(info)
	printOrders(info)
	printPortfolios(info)
	printPaymentMethods(info)
	printWallets(info)
	printAddresses(info)
}

func printAccounts(info *secretInfo) {
	color.Yellow("\n[i] Accounts:")
	accountsTable := table.NewWriter()
	accountsTable.AppendHeader(table.Row{
		"UUID",
		"Name",
		"Type",
		"Currency",
		"Balance",
		"Active",
		"Created At",
		"Updated At",
		"Deleted At",
	})

	for _, account := range info.Accounts {
		accountsTable.AppendRow(table.Row{
			account.UUID,
			account.Name,
			account.Type,
			account.Currency,
			account.AvailableBalance.Value,
			account.Active,
			account.CreatedAt,
			account.UpdatedAt,
			account.DeletedAt,
		})
		accountsTable.AppendSeparator()
	}

	accountsTable.SetOutputMirror(os.Stdout)
	accountsTable.Render()
}

func printOrders(info *secretInfo) {
	color.Yellow("\n[i] Orders:")
	ordersTable := table.NewWriter()
	ordersTable.AppendHeader(table.Row{
		"ID",
		"Type",
		"Product ID",
		"Product Type",
		"User ID",
		"Client Order ID",
		"Status",
		"Fee",
		"Create Time",
	})

	for _, order := range info.Orders {
		ordersTable.AppendRow(table.Row{
			order.OrderID,
			order.OrderType,
			order.ProductID,
			order.ProductType,
			order.UserID,
			order.ClientOrderID,
			order.Status,
			order.Fee,
			order.CreatedTime,
		})
		ordersTable.AppendSeparator()
	}

	ordersTable.SetOutputMirror(os.Stdout)
	ordersTable.Render()
}

func printPortfolios(info *secretInfo) {
	color.Yellow("\n[i] Portfolios:")
	portfoliosTable := table.NewWriter()
	portfoliosTable.AppendHeader(table.Row{"UUID", "Name", "Type", "Deleted"})

	for _, portfolio := range info.Portfolios {
		portfoliosTable.AppendRow(table.Row{
			portfolio.UUID,
			portfolio.Name,
			portfolio.Type,
			portfolio.Deleted,
		})
		portfoliosTable.AppendSeparator()
	}

	portfoliosTable.SetOutputMirror(os.Stdout)
	portfoliosTable.Render()
}

func printPaymentMethods(info *secretInfo) {
	color.Yellow("\n[i] Payment Methods:")
	paymentMethodsTable := table.NewWriter()
	paymentMethodsTable.AppendHeader(table.Row{
		"ID",
		"Type",
		"Name",
		"Currency",
		"Verified",
		"Created At",
		"Updated At",
	})

	for _, paymentMethod := range info.PaymentMethods {
		paymentMethodsTable.AppendRow(table.Row{
			paymentMethod.ID,
			paymentMethod.Type,
			paymentMethod.Name,
			paymentMethod.Currency,
			paymentMethod.Verified,
			paymentMethod.CreatedAt,
			paymentMethod.UpdatedAt,
		})
		paymentMethodsTable.AppendSeparator()
	}

	paymentMethodsTable.SetOutputMirror(os.Stdout)
	paymentMethodsTable.Render()
}

func printWallets(info *secretInfo) {
	color.Yellow("\n[i] Wallets:")
	walletsTable := table.NewWriter()
	walletsTable.AppendHeader(table.Row{
		"ID",
		"Network ID",
		"Server Signer Status",
	})

	for _, wallet := range info.Wallets {
		walletsTable.AppendRow(table.Row{
			wallet.ID,
			wallet.NetworkID,
			wallet.ServerSignerStatus,
		})
		walletsTable.AppendSeparator()
	}

	walletsTable.SetOutputMirror(os.Stdout)
	walletsTable.Render()
}

func printAddresses(info *secretInfo) {
	color.Yellow("\n[i] Wallet Addresses:")
	addressesTable := table.NewWriter()
	addressesTable.AppendHeader(table.Row{
		"Wallet ID",
		"Network ID",
		"Public Key",
		"Address ID",
	})

	for _, address := range info.Addresses {
		addressesTable.AppendRow(table.Row{
			address.WalletID,
			address.NetworkID,
			address.PublicKey,
			address.AddressID,
		})
		addressesTable.AppendSeparator()
	}

	addressesTable.SetOutputMirror(os.Stdout)
	addressesTable.Render()
}
