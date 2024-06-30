package mailgun

import (
	"encoding/json"
	"net/http"
	"os"
	"strconv"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/table"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
)

type Domain struct {
	URL        string `json:"name"`
	IsDisabled bool   `json:"is_disabled"`
	Type       string `json:"type"`
	State      string `json:"state"`
	CreatedAt  string `json:"created_at"`
}

type DomainsJSON struct {
	Items      []Domain `json:"items"`
	TotalCount int      `json:"total_count"`
}

func getDomains(cfg *config.Config, apiKey string) (DomainsJSON, int, error) {
	var domainsJSON DomainsJSON

	client := analyzers.NewAnalyzeClient(cfg)
	req, err := http.NewRequest("GET", "https://api.mailgun.net/v4/domains", nil)
	if err != nil {
		return domainsJSON, -1, err
	}

	req.SetBasicAuth("api", apiKey)
	resp, err := client.Do(req)
	if err != nil {
		return domainsJSON, -1, err
	}

	if resp.StatusCode != 200 {
		return domainsJSON, resp.StatusCode, nil
	}

	defer resp.Body.Close()

	err = json.NewDecoder(resp.Body).Decode(&domainsJSON)
	if err != nil {
		return domainsJSON, resp.StatusCode, err
	}
	return domainsJSON, resp.StatusCode, nil
}

func AnalyzePermissions(cfg *config.Config, apiKey string) {
	// Get the domains associated with the API key
	domains, statusCode, err := getDomains(cfg, apiKey)
	if err != nil {
		color.Red("[x] Error getting domains: %s", err)
		return
	}

	if statusCode != 200 {
		color.Red("[x] Invalid Mailgun API key.")
		return
	}
	color.Green("[i] Valid Mailgun API key\n\n")
	color.Green("[i] Permissions: Full Access\n\n")
	// Print the domains
	printDomains(domains)
}

func printDomains(domains DomainsJSON) {
	if domains.TotalCount == 0 {
		color.Red("[i] No domains found")
		return
	}
	color.Yellow("[i] Found %d domain(s)", domains.TotalCount)
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Domain", "Type", "State", "Created At", "Disabled"})
	for _, domain := range domains.Items {
		if domain.IsDisabled {
			t.AppendRow([]interface{}{color.RedString(domain.URL), color.RedString(domain.Type), color.RedString(domain.State), color.RedString(domain.CreatedAt), color.RedString(strconv.FormatBool(domain.IsDisabled))})
		} else if domain.Type == "sandbox" || domain.State == "unverified" {
			t.AppendRow([]interface{}{color.YellowString(domain.URL), color.YellowString(domain.Type), color.YellowString(domain.State), color.YellowString(domain.CreatedAt), color.YellowString(strconv.FormatBool(domain.IsDisabled))})
		} else {
			t.AppendRow([]interface{}{color.GreenString(domain.URL), color.GreenString(domain.Type), color.GreenString(domain.State), color.GreenString(domain.CreatedAt), color.GreenString(strconv.FormatBool(domain.IsDisabled))})
		}
	}
	t.Render()
}
