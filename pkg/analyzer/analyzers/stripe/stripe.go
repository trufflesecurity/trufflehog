//go:generate generate_permissions permissions.yaml permissions.go stripe

package stripe

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"gopkg.in/yaml.v2"
)

var _ analyzers.Analyzer = (*Analyzer)(nil)

type Analyzer struct {
	Cfg *config.Config
}

func (Analyzer) Type() analyzers.AnalyzerType { return analyzers.AnalyzerTypeStripe }

func (a Analyzer) Analyze(_ context.Context, credInfo map[string]string) (*analyzers.AnalyzerResult, error) {
	key, ok := credInfo["key"]
	if !ok {
		return nil, analyzers.NewAnalysisError("Stripe", "validate_credentials", "config", "", errors.New("key not found in credentialInfo"))
	}

	info, err := AnalyzePermissions(a.Cfg, key)
	if err != nil {
		return nil, analyzers.NewAnalysisError("Stripe", "analyze_permissions", "API", "", err)
	}
	return secretInfoToAnalyzerResult(info), nil
}

func secretInfoToAnalyzerResult(info *SecretInfo) *analyzers.AnalyzerResult {
	if info == nil {
		return nil
	}
	result := &analyzers.AnalyzerResult{
		AnalyzerType: analyzers.AnalyzerTypeStripe,
		Metadata: map[string]any{
			"key_type": info.KeyType,
			"key_env":  info.KeyEnv,
		},
	}

	// create list of bindings using permissions, with category being the parent and unbounded resource
	result.Bindings = []analyzers.Binding{}
	result.UnboundedResources = []analyzers.Resource{}
	for _, permissionCategory := range info.Permissions {
		parentResource := &analyzers.Resource{
			Name:               permissionCategory.Name,
			FullyQualifiedName: permissionCategory.Name,
			Type:               "category",
			Metadata:           nil,
			Parent:             nil,
		}
		if len(permissionCategory.Permissions) == 0 {
			result.UnboundedResources = append(result.UnboundedResources, *parentResource)
		} else {
			for _, permission := range permissionCategory.Permissions {
				if _, ok := StringToPermission[*permission.Value]; !ok { // skip unknown scopes/permission
					continue
				}
				result.Bindings = append(result.Bindings, analyzers.Binding{
					Resource: *parentResource,
					Permission: analyzers.Permission{
						Value: fmt.Sprintf("%s:%s", permission.Name, *permission.Value),
					},
				})
			}
		}
	}

	return result

}

const (
	SECRET_PREFIX      = "sk_"
	PUBLISHABLE_PREFIX = "pk_"
	RESTRICTED_PREFIX  = "rk_"
	LIVE_PREFIX        = "live_"
	TEST_PREFIX        = "test_"
	SECRET             = "Secret"
	PUBLISHABLE        = "Publishable"
	RESTRICTED         = "Restricted"
	LIVE               = "Live"
	TEST               = "Test"
)

//go:embed restricted.yaml
var restrictedConfig []byte

type PermissionStruct struct {
	Name  string
	Value *string
}

type PermissionsCategory struct {
	Name        string
	Permissions []PermissionStruct
}

type HttpStatusTest struct {
	Endpoint        string      `yaml:"Endpoint"`
	Method          string      `yaml:"Method"`
	Payload         interface{} `yaml:"Payload"`
	ValidStatuses   []int       `yaml:"Valid"`
	InvalidStatuses []int       `yaml:"Invalid"`
}

type Category map[string]map[string]HttpStatusTest

type Config struct {
	Categories map[string]Category `yaml:"categories"`
}

type SecretInfo struct {
	KeyType     string
	KeyEnv      string
	Valid       bool
	Permissions []PermissionsCategory
}

func (h *HttpStatusTest) RunTest(cfg *config.Config, headers map[string]string) (bool, error) {
	// If body data, marshal to JSON
	var data io.Reader
	if h.Payload != nil {
		jsonData, err := json.Marshal(h.Payload)
		if err != nil {
			return false, err
		}
		data = bytes.NewBuffer(jsonData)
	}

	// Create new HTTP request
	client := analyzers.NewAnalyzeClient(cfg)
	req, err := http.NewRequest(h.Method, h.Endpoint, data)
	if err != nil {
		return false, err
	}

	// Add custom headers if provided
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	// Execute HTTP Request
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	// Check response status code
	switch {
	case StatusContains(resp.StatusCode, h.ValidStatuses):
		return true, nil
	case StatusContains(resp.StatusCode, h.InvalidStatuses):
		return false, nil
	default:
		fmt.Println(h)
		fmt.Println(resp.Body)
		fmt.Println(resp.StatusCode)
		return false, errors.New("error checking response status code")
	}
}

func StatusContains(status int, vals []int) bool {
	for _, v := range vals {
		if status == v {
			return true
		}
	}
	return false
}

func checkKeyType(key string) (string, error) {
	if strings.HasPrefix(key, SECRET_PREFIX) {
		return SECRET, nil
	} else if strings.HasPrefix(key, PUBLISHABLE_PREFIX) {
		return PUBLISHABLE, nil
	} else if strings.HasPrefix(key, RESTRICTED_PREFIX) {
		return RESTRICTED, nil
	}
	return "", errors.New("Invalid Stripe key format")
}

func checkKeyEnv(key string) (string, error) {
	//remove first 3 characters
	key = key[3:]
	if strings.HasPrefix(key, LIVE_PREFIX) {
		return LIVE, nil
	}
	if strings.HasPrefix(key, TEST_PREFIX) {
		return TEST, nil
	}
	return "", errors.New("invalid Stripe key format")
}

func checkValidity(cfg *config.Config, key string) (bool, error) {
	// Create a new request
	client := analyzers.NewAnalyzeClient(cfg)
	req, err := http.NewRequest("GET", "https://api.stripe.com/v1/charges", nil)
	if err != nil {
		return false, err
	}

	// Add Authorization header
	req.Header.Add("Authorization", "Bearer "+key)

	// Send the request
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	// Check the response. Valid is 200 (secret/restricted) or 403 (restricted)
	if resp.StatusCode == 200 || resp.StatusCode == 403 {
		return true, nil
	}
	return false, nil
}

func AnalyzePermissions(cfg *config.Config, key string) (*SecretInfo, error) {
	// Check if secret, publishable, or restricted key
	var keyType, keyEnv string
	keyType, err := checkKeyType(key)
	if err != nil {
		return nil, err
	}

	// Check if live or test key
	keyEnv, err = checkKeyEnv(key)
	if err != nil {
		return nil, err
	}

	// Check if key is valid
	valid, err := checkValidity(cfg, key)
	if err != nil {
		return nil, err
	}

	permissions, err := getRestrictedPermissions(cfg, key)
	if err != nil {
		return nil, err
	}
	// Additional details
	// get total customers
	// get total charges

	return &SecretInfo{
		KeyType:     keyType,
		KeyEnv:      keyEnv,
		Valid:       valid,
		Permissions: permissions,
	}, nil
}

func AnalyzeAndPrintPermissions(cfg *config.Config, key string) {
	info, err := AnalyzePermissions(cfg, key)
	if err != nil {
		color.Red("[x] Error: %s", err.Error())
		return
	}

	if info.KeyType == PUBLISHABLE {
		color.Red("[x] This is a publishable Stripe key. It is not considered secret.")
		return
	}

	if !info.Valid {
		color.Red("[x] Invalid Stripe API Key\n")
		return
	}

	color.Green("[!] Valid Stripe API Key\n\n")

	if info.KeyType == SECRET {
		color.Green("[i] Key Type: %s", info.KeyType)
	} else if info.KeyType == RESTRICTED {
		color.Yellow("[i] Key Type: %s", info.KeyType)
	}

	if info.KeyEnv == LIVE {
		color.Green("[i] Key Environment: %s", info.KeyEnv)
	} else if info.KeyEnv == TEST {
		color.Red("[i] Key Environment: %s", info.KeyEnv)
	}

	fmt.Println("")

	if info.KeyType == SECRET {
		color.Green("[i] Permissions: Full Access")
		return
	}

	printRestrictedPermissions(info.Permissions, cfg.ShowAll)
}

func getRestrictedPermissions(cfg *config.Config, key string) ([]PermissionsCategory, error) {
	var config Config
	if err := yaml.Unmarshal(restrictedConfig, &config); err != nil {
		fmt.Println("Error unmarshalling YAML:", err)
		return nil, err
	}

	output := make([]PermissionsCategory, 0)

	for category, scopes := range config.Categories {
		permissions := make([]PermissionStruct, 0)
		for name, scope := range scopes {
			value := ""
			testCount := 0
			for typ, test := range scope {
				if test.Endpoint == "" {
					continue
				}
				testCount++
				status, err := test.RunTest(cfg, map[string]string{"Authorization": "Bearer " + key})
				if err != nil {
					color.Red("[x] Error running test: %s", err.Error())
					return nil, err
				}
				if status {
					value = typ
				}
				if value == "Write" {
					break
				}
			}
			if testCount > 0 {
				permissions = append(permissions, PermissionStruct{Name: name, Value: &value})
			}
		}
		output = append(output, PermissionsCategory{Name: category, Permissions: permissions})
	}

	// sort the output
	order := []string{"Core", "Checkout", "Billing", "Connect", "Orders", "Issuing", "Reporting", "Identity", "Webhook", "Stripe CLI", "Payment Links", "Terminal", "Tax", "Radar", "Climate"}
	// ToDo: order the permissions within each category

	// Create a map for quick lookup of the order
	orderMap := make(map[string]int)
	for i, name := range order {
		orderMap[name] = i
	}

	// Sort the categories according to the desired order
	sort.Slice(output, func(i, j int) bool {
		return orderMap[output[i].Name] < orderMap[output[j].Name]
	})

	return output, nil

}

func printRestrictedPermissions(permissions []PermissionsCategory, show_all bool) {
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Category", "Permission", "Access"})
	for _, category := range permissions {
		for _, permission := range category.Permissions {
			if *permission.Value != "" || show_all {
				t.AppendRow([]interface{}{category.Name, permission.Name, *permission.Value})
			}
		}
	}
	t.Render()
}
