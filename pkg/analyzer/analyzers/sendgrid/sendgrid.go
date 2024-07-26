package sendgrid

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/v6/table"
	sg "github.com/sendgrid/sendgrid-go"

	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
)

type ScopesJSON struct {
	Scopes []string `json:"scopes"`
}

type SecretInfo struct {
	RawScopes []string
}

func printPermissions(show_all bool) {
	fmt.Print("\n\n")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	if show_all {
		t.AppendHeader(table.Row{"Scope", "Sub-Scope", "Access", "Permissions"})
	} else {
		t.AppendHeader(table.Row{"Scope", "Sub-Scope", "Access"})
	}
	// Print the scopes
	for _, s := range SCOPES {
		writer := analyzers.GetWriterFromStatus(s.PermissionType)
		if show_all {
			t.AppendRow([]interface{}{writer(s.Category), writer(s.SubCategory), writer(s.PermissionType), writer(strings.Join(s.Permissions, "\n"))})
		} else if s.PermissionType != analyzers.NONE {
			t.AppendRow([]interface{}{writer(s.Category), writer(s.SubCategory), writer(s.PermissionType)})
		}
	}
	t.Render()
	fmt.Print("\n\n")
}

// getCategoryFromScope returns the category for a given scope.
// It will return the most specific category possible.
// For example, if the scope is "mail.send.read", it will return "Mail Send", not just "Mail"
// since it's searching "mail.send.read" -> "mail.send" -> "mail"
func getScopeIndex(scope string) int {
	splitScope := strings.Split(scope, ".")
	for i := len(splitScope); i > 0; i-- {
		searchScope := strings.Join(splitScope[:i], ".")
		for i, s := range SCOPES {
			for _, prefix := range s.Prefixes {
				if strings.HasPrefix(searchScope, prefix) {
					return i
				}
			}
		}
	}
	return -1
}

func processPermissions(rawScopes []string) {
	for _, scope := range rawScopes {
		// Skip these scopes since they are not useful for this analysis
		if scope == "2fa_required" || scope == "sender_verification_eligible" {
			continue
		}
		ind := getScopeIndex(scope)
		if ind == -1 {
			//color.Red("[!] Scope not found: %v", scope)
			continue
		}
		s := &SCOPES[ind]
		s.AddPermission(scope)
	}
	// Run tests to determine the permission type
	for i := range SCOPES {
		SCOPES[i].RunTests()
	}
}

func AnalyzeAndPrintPermissions(cfg *config.Config, key string) {

	// ToDo: Add logging when rewrite to not use SG client.
	if cfg.LoggingEnabled {
		color.Red("[x] Logging not supported for GitHub Token Analysis.")
		return
	}

	info, err := AnalyzePermissions(cfg, key)
	if err != nil {
		color.Red("[!] Error: %v", err)
		return
	}

	color.Green("[!] Valid Sendgrid API Key\n\n")

	if slices.Contains(info.RawScopes, "user.email.read") {
		color.Green("[*] Sendgrid Key Type: Full Access Key")
	} else if slices.Contains(info.RawScopes, "billing.read") {
		color.Yellow("[*] Sendgrid Key Type: Billing Access Key")
	} else {
		color.Yellow("[*] Sendgrid Key Type: Restricted Access Key")
	}

	if slices.Contains(info.RawScopes, "2fa_required") {
		color.Yellow("[i] 2FA Required for this account")
	}

	printPermissions(cfg.ShowAll)
}

func AnalyzePermissions(cfg *config.Config, key string) (*SecretInfo, error) {

	req := sg.GetRequest(key, "/v3/scopes", "https://api.sendgrid.com")
	req.Method = "GET"
	resp, err := sg.API(req)
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return nil, fmt.Errorf("Invalid API Key")
	} else if resp.StatusCode != 200 {
		return nil, fmt.Errorf("%v", resp.StatusCode)
	}
	if err != nil {
		return nil, err
	}

	// Unmarshal the JSON response into a struct
	var jsonScopes ScopesJSON
	if err := json.Unmarshal([]byte(resp.Body), &jsonScopes); err != nil {
		return nil, err
	}

	// Now you can access the scopes
	rawScopes := jsonScopes.Scopes

	processPermissions(rawScopes)

	return &SecretInfo{RawScopes: rawScopes}, nil
}
