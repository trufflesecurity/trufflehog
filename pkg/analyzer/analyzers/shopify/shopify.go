package shopify

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/table"
)

func sliceContains(slice []string, value string) bool {
	for _, v := range slice {
		if v == value {
			return true
		}
	}
	return false
}

type OutputScopes struct {
	Description string
	Scopes      []string
}

func (o OutputScopes) PrintScopes() string {
	// Custom rules unique to this analyzer
	var scopes []string
	if sliceContains(o.Scopes, "Read") && sliceContains(o.Scopes, "Write") {
		scopes = append(scopes, "Read & Write")
		for _, scope := range o.Scopes {
			if scope != "Read" && scope != "Write" {
				scopes = append(scopes, scope)
			}
		}
	} else {
		scopes = append(scopes, o.Scopes...)
	}
	return strings.Join(scopes, ", ")
}

// Category represents the structure of each category in the JSON
type CategoryJSON struct {
	Description string            `json:"description"`
	Scopes      map[string]string `json:"scopes"`
}

// Data represents the overall JSON structure
type ScopeDataJSON struct {
	Categories map[string]CategoryJSON `json:"categories"`
}

// Function to determine the appropriate scope
func determineScopes(data ScopeDataJSON, input string) map[string]OutputScopes {
	// Split the input string into individual scopes
	inputScopes := strings.Split(input, ", ")

	// Map to store scopes found for each category
	scopeResults := make(map[string]OutputScopes)

	// Populate categoryScopes map with individual scopes found
	for _, scope := range inputScopes {
		for category, catData := range data.Categories {
			if scopeType, exists := catData.Scopes[scope]; exists {
				if _, ok := scopeResults[category]; !ok {
					scopeResults[category] = OutputScopes{Description: catData.Description}
				}
				// Extract the struct from the map
				outputData := scopeResults[category]

				// Modify the struct (ex: append "Read" or "Write" to the Scopes slice)
				outputData.Scopes = append(outputData.Scopes, scopeType)

				// Reassign the modified struct back to the map
				scopeResults[category] = outputData
			}
		}
	}

	return scopeResults
}

type ShopInfoJSON struct {
	Shop struct {
		Name      string `json:"name"`
		Email     string `json:"email"`
		CreatedAt string `json:"created_at"`
	} `json:"shop"`
}

func getShopInfo(key string, store string) (ShopInfoJSON, error) {
	var shopInfo ShopInfoJSON

	client := &http.Client{}
	req, err := http.NewRequest("GET", fmt.Sprintf("https://%s/admin/api/2024-04/shop.json", store), nil)
	if err != nil {
		return shopInfo, err
	}

	req.Header.Set("X-Shopify-Access-Token", key)

	resp, err := client.Do(req)
	if err != nil {
		return shopInfo, err
	}

	defer resp.Body.Close()

	err = json.NewDecoder(resp.Body).Decode(&shopInfo)
	if err != nil {
		return shopInfo, err
	}
	return shopInfo, nil
}

type AccessScopesJSON struct {
	AccessScopes []struct {
		Handle string `json:"handle"`
	} `json:"access_scopes"`
}

func (a AccessScopesJSON) String() string {
	var scopes []string
	for _, scope := range a.AccessScopes {
		scopes = append(scopes, scope.Handle)
	}
	return strings.Join(scopes, ", ")
}

func getAccessScopes(key string, store string) (AccessScopesJSON, int, error) {
	var accessScopes AccessScopesJSON

	client := &http.Client{}
	req, err := http.NewRequest("GET", fmt.Sprintf("https://%s/admin/oauth/access_scopes.json", store), nil)
	if err != nil {
		return accessScopes, -1, err
	}

	req.Header.Set("X-Shopify-Access-Token", key)

	resp, err := client.Do(req)
	if err != nil {
		return accessScopes, resp.StatusCode, err
	}

	defer resp.Body.Close()

	err = json.NewDecoder(resp.Body).Decode(&accessScopes)
	if err != nil {
		return accessScopes, resp.StatusCode, err
	}
	return accessScopes, resp.StatusCode, nil
}

func AnalyzePermissions(key string, storeURL string, showAll bool) {

	accessScopes, statusCode, err := getAccessScopes(key, storeURL)
	if err != nil {
		color.Red("Error: %s", err)
		return
	}

	if statusCode != 200 {
		color.Red("[x] Invalid Shopfiy API Key and Store URL combination")
		return
	}
	color.Green("[i] Valid Shopify API Key\n\n")

	shopInfo, err := getShopInfo(key, storeURL)
	if err != nil {
		color.Red("Error: %s", err)
		return
	}

	color.Yellow("[i] Shop Information\n")
	color.Yellow("Name: %s", shopInfo.Shop.Name)
	color.Yellow("Email: %s", shopInfo.Shop.Email)
	color.Yellow("Created At: %s\n\n", shopInfo.Shop.CreatedAt)

	// Determine the current working directory
	cwd, err := os.Getwd()
	if err != nil {
		color.Red("[x] Error getting current working directory: %s", err.Error())
		return
	}

	// Construct the path to the config file
	configFilePath := filepath.Join(cwd, "pkg/analyzers/shopify/scopes.json")
	jsonData, err := os.ReadFile(configFilePath)
	if err != nil {
		color.Red("Error: %s", err)
		return
	}

	var data ScopeDataJSON
	err = json.Unmarshal([]byte(jsonData), &data)
	if err != nil {
		color.Red("Error: %s", err)
		return
	}
	scopes := determineScopes(data, accessScopes.String())
	printAccessScopes(scopes)
}

func printAccessScopes(accessScopes map[string]OutputScopes) {
	color.Yellow("[i] Access Scopes\n")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Scope", "Description", "Access"})

	// order the categories
	categoryOrder := []string{"Analytics", "Applications", "Assigned fulfillment orders", "Browsing behavior", "Custom pixels", "Customers", "Discounts", "Discovery", "Draft orders", "Files", "Fulfillment services", "Gift cards", "Inventory", "Legal policies", "Locations", "Marketing events", "Merchant-managed fulfillment orders", "Metaobject definitions", "Metaobject entries", "Online Store navigation", "Online Store pages", "Order editing", "Orders", "Packing slip management", "Payment customizations", "Payment terms", "Pixels", "Price rules", "Product feeds", "Product listings", "Products", "Publications", "Purchase options", "Reports", "Resource feedback", "Returns", "Sales channels", "Script tags", "Shipping", "Shop locales", "Shopify Markets", "Shopify Payments accounts", "Shopify Payments bank accounts", "Shopify Payments disputes", "Shopify Payments payouts", "Store content", "Store credit account transactions", "Store credit accounts", "Themes", "Third-party fulfillment orders", "Translations", "all_cart_transforms", "all_checkout_completion_target_customizations", "cart_transforms", "cash_tracking", "companies", "custom_fulfillment_services", "customer_data_erasure", "customer_merge", "delivery_customizations", "delivery_option_generators", "discounts_allocator_functions", "fulfillment_constraint_rules", "gates", "order_submission_rules", "privacy_settings", "shopify_payments_provider_accounts_sensitive", "validations"}

	for _, category := range categoryOrder {
		if val, ok := accessScopes[category]; ok {
			t.AppendRow([]interface{}{color.GreenString(category), color.GreenString(val.Description), color.GreenString(val.PrintScopes())})
		}
	}
	t.Render()

}
