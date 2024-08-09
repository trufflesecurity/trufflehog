package mailgun

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/table"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/pb/analyzerpb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

var _ analyzers.Analyzer = (*Analyzer)(nil)

type Analyzer struct {
	Cfg *config.Config
}

func (Analyzer) Type() analyzerpb.AnalyzerType { return analyzerpb.AnalyzerType_Mailgun }

func (a Analyzer) Analyze(_ context.Context, credInfo map[string]string) (*analyzers.AnalyzerResult, error) {
	_, err := AnalyzePermissions(a.Cfg, credInfo["key"])
	if err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("not implemented")
}

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

func AnalyzeAndPrintPermissions(cfg *config.Config, apiKey string) {
	data, err := AnalyzePermissions(cfg, apiKey)
	if err != nil {
		color.Red("[x] %s", err.Error())
		return
	}

	printMetadata(data)
}

func AnalyzePermissions(cfg *config.Config, apiKey string) (*DomainsJSON, error) {
	// Get the domains associated with the API key
	domains, statusCode, err := getDomains(cfg, apiKey)
	if err != nil {
		return nil, fmt.Errorf("Error getting domains: %s", err)
	}

	if statusCode != 200 {
		return nil, fmt.Errorf("Invalid Mailgun API key.")
	}
	color.Green("[i] Valid Mailgun API key\n\n")
	color.Green("[i] Permissions: Full Access\n\n")

	return &domains, nil
}

func printMetadata(domains *DomainsJSON) {
	if domains.TotalCount == 0 {
		color.Red("[i] No domains found")
		return
	}
	color.Yellow("[i] Found %d domain(s)", domains.TotalCount)

	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Domain", "Type", "State", "Created At", "Disabled"})

	for _, domain := range domains.Items {

		var colorFunc func(format string, a ...interface{}) string
		switch {
		case domain.IsDisabled:
			colorFunc = color.RedString
		case domain.Type == "sandbox" || domain.State == "unverified":
			colorFunc = color.YellowString
		default:
			colorFunc = color.GreenString
		}

		t.AppendRow([]interface{}{
			colorFunc(domain.URL),
			colorFunc(domain.Type),
			colorFunc(domain.State),
			colorFunc(domain.CreatedAt),
			colorFunc(strconv.FormatBool(domain.IsDisabled)),
		})
	}
	t.Render()
}
