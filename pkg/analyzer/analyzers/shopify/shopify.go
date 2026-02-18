//go:generate generate_permissions permissions.yaml permissions.go shopify

package shopify

import (
	_ "embed"
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

var (
	// order the categories
	categoryOrder = []string{"Analytics", "Applications", "Assigned fulfillment orders", "Browsing behavior", "Custom pixels", "Customers", "Discounts", "Discovery", "Draft orders", "Files", "Fulfillment services", "Gift cards", "Inventory", "Legal policies", "Locations", "Marketing events", "Merchant-managed fulfillment orders", "Metaobject definitions", "Metaobject entries", "Online Store navigation", "Online Store pages", "Order editing", "Orders", "Packing slip management", "Payment customizations", "Payment terms", "Pixels", "Price rules", "Product feeds", "Product listings", "Products", "Publications", "Purchase options", "Reports", "Resource feedback", "Returns", "Sales channels", "Script tags", "Shipping", "Shop locales", "Shopify Markets", "Shopify Payments accounts", "Shopify Payments bank accounts", "Shopify Payments disputes", "Shopify Payments payouts", "Store content", "Store credit account transactions", "Store credit accounts", "Themes", "Third-party fulfillment orders", "Translations", "all_cart_transforms", "all_checkout_completion_target_customizations", "cart_transforms", "cash_tracking", "companies", "custom_fulfillment_services", "customer_data_erasure", "customer_merge", "delivery_customizations", "delivery_option_generators", "discounts_allocator_functions", "fulfillment_constraint_rules", "gates", "order_submission_rules", "privacy_settings", "shopify_payments_provider_accounts_sensitive", "validations"}
)

func (Analyzer) Type() analyzers.AnalyzerType { return analyzers.AnalyzerTypeShopify }

func (a Analyzer) Analyze(_ context.Context, credInfo map[string]string) (*analyzers.AnalyzerResult, error) {
	key, ok := credInfo["key"]
	if !ok {
		return nil, analyzers.NewAnalysisError("Shopify", "validate_credentials", "config", "", errors.New("key not found in credentialInfo"))
	}

	storeUrl, ok := credInfo["store_url"]
	if !ok {
		return nil, analyzers.NewAnalysisError("Shopify", "validate_credentials", "config", "", errors.New("store_url not found in credentialInfo"))
	}

	info, err := AnalyzePermissions(a.Cfg, key, storeUrl)
	if err != nil {
		return nil, analyzers.NewAnalysisError("Shopify", "analyze_permissions", "API", "", err)
	}
	return secretInfoToAnalyzerResult(info), nil
}

func secretInfoToAnalyzerResult(info *SecretInfo) *analyzers.AnalyzerResult {
	if info == nil {
		return nil
	}
	result := analyzers.AnalyzerResult{
		AnalyzerType: analyzers.AnalyzerTypeShopify,
		Metadata: map[string]any{
			"status_code": info.StatusCode,
		},
	}

	resource := &analyzers.Resource{
		Name:               info.ShopInfo.Shop.Name,
		FullyQualifiedName: info.ShopInfo.Shop.Domain + "/" + info.ShopInfo.Shop.Email,
		Type:               "shop",
		Metadata: map[string]any{
			"created_at": info.ShopInfo.Shop.CreatedAt,
		},
		Parent: nil,
	}
	result.Bindings = make([]analyzers.Binding, 0)

	for _, category := range categoryOrder {
		if val, ok := info.Scopes[category]; ok {
			cateogryResource := &analyzers.Resource{
				Name:               category,
				FullyQualifiedName: resource.FullyQualifiedName + "/" + category, // shop.domain/shop.email/category
				Type:               "category",
				Parent:             resource,
			}

			if sliceContains(val.Scopes, "Read") && sliceContains(val.Scopes, "Write") {
				result.Bindings = append(result.Bindings, analyzers.Binding{
					Resource: *cateogryResource,
					Permission: analyzers.Permission{
						Value: PermissionStrings[FullAccess],
					},
				})
				continue
			}

			for _, scope := range val.Scopes {
				lowerScope := strings.ToLower(scope)
				if _, ok := StringToPermission[lowerScope]; !ok { // skip unknown scopes/permission
					continue
				}
				result.Bindings = append(result.Bindings, analyzers.Binding{
					Resource: *cateogryResource,
					Permission: analyzers.Permission{
						Value: lowerScope,
					},
				})
			}
		}
	}

	return &result
}

//go:embed scopes.json
var scopesConfig []byte

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
		Domain    string `json:"domain"`
		Name      string `json:"name"`
		Email     string `json:"email"`
		CreatedAt string `json:"created_at"`
	} `json:"shop"`
}

type SecretInfo struct {
	StatusCode int
	ShopInfo   ShopInfoJSON
	Scopes     map[string]OutputScopes
}

func getShopInfo(cfg *config.Config, key string, store string) (ShopInfoJSON, error) {
	var shopInfo ShopInfoJSON

	client := analyzers.NewAnalyzeClient(cfg)
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

func getAccessScopes(cfg *config.Config, key string, store string) (AccessScopesJSON, int, error) {
	var accessScopes AccessScopesJSON

	client := analyzers.NewAnalyzeClient(cfg)
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

func AnalyzeAndPrintPermissions(cfg *config.Config, key string, storeURL string) {
	// ToDo: Add in logging
	if cfg.LoggingEnabled {
		color.Red("[x] Logging is not supported for this analyzer.")
		return
	}

	info, err := AnalyzePermissions(cfg, key, storeURL)
	if err != nil {
		color.Red("[x] Error: %s", err.Error())
		return
	}

	if info.StatusCode != 200 {
		color.Red("[x] Invalid Shopfiy API Key and Store URL combination")
		return
	}
	color.Green("[i] Valid Shopify API Key\n\n")

	color.Yellow("[i] Shop Information\n")
	color.Yellow("Name: %s", info.ShopInfo.Shop.Name)
	color.Yellow("Email: %s", info.ShopInfo.Shop.Email)
	color.Yellow("Created At: %s\n\n", info.ShopInfo.Shop.CreatedAt)

	printAccessScopes(info.Scopes)
}

func AnalyzePermissions(cfg *config.Config, key string, storeURL string) (*SecretInfo, error) {

	accessScopes, statusCode, err := getAccessScopes(cfg, key, storeURL)
	if err != nil {
		return nil, err
	}

	shopInfo, err := getShopInfo(cfg, key, storeURL)
	if err != nil {
		return nil, err
	}

	var data ScopeDataJSON
	if err := json.Unmarshal(scopesConfig, &data); err != nil {
		return nil, err
	}
	scopes := determineScopes(data, accessScopes.String())

	return &SecretInfo{
		StatusCode: statusCode,
		ShopInfo:   shopInfo,
		Scopes:     scopes,
	}, nil
}

func printAccessScopes(accessScopes map[string]OutputScopes) {
	color.Yellow("[i] Access Scopes\n")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Scope", "Description", "Access"})

	for _, category := range categoryOrder {
		if val, ok := accessScopes[category]; ok {
			t.AppendRow([]interface{}{color.GreenString(category), color.GreenString(val.Description), color.GreenString(val.PrintScopes())})
		}
	}
	t.Render()

}
