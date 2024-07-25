package mailchimp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/table"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
)

var BASE_URL = "https://%s.api.mailchimp.com/3.0"

type MetadataJSON struct {
	AccountID       string `json:"account_id"`
	AccountName     string `json:"account_name"`
	Email           string `json:"email"`
	FirstName       string `json:"first_name"`
	LastName        string `json:"last_name"`
	Role            string `json:"role"`
	MemberSince     string `json:"member_since"`
	PricingPlan     string `json:"pricing_plan_type"`
	AccountTimezone string `json:"account_timezone"`
	Contact         struct {
		Company  string `json:"company"`
		Address1 string `json:"addr1"`
		Address2 string `json:"addr2"`
		City     string `json:"city"`
		State    string `json:"state"`
		Zip      string `json:"zip"`
		Country  string `json:"country"`
	} `json:"contact"`
	LastLogin        string `json:"last_login"`
	TotalSubscribers int    `json:"total_subscribers"`
}

type DomainsJSON struct {
	Domains []struct {
		Domain        string `json:"domain"`
		Authenticated bool   `json:"authenticated"`
		Verified      bool   `json:"verified"`
	} `json:"domains"`
}

func getMetadata(cfg *config.Config, key string) (MetadataJSON, error) {
	var metadata MetadataJSON

	// extract datacenter
	keySplit := strings.Split(key, "-")
	if len(keySplit) != 2 {
		return metadata, nil
	}
	datacenter := keySplit[1]

	client := analyzers.NewAnalyzeClient(cfg)
	req, err := http.NewRequest("GET", fmt.Sprintf(BASE_URL, datacenter), nil)
	if err != nil {
		color.Red("[x] Error: %s", err)
		return metadata, err
	}

	req.SetBasicAuth("anystring", key)
	resp, err := client.Do(req)
	if err != nil {
		color.Red("[x] Error: %s", err)
		return metadata, err
	}

	defer resp.Body.Close()

	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		color.Red("[x] Error: %s", err)
		return metadata, err
	}

	return metadata, nil
}

func getDomains(cfg *config.Config, key string) (DomainsJSON, error) {
	var domains DomainsJSON

	// extract datacenter
	keySplit := strings.Split(key, "-")
	if len(keySplit) != 2 {
		return domains, nil
	}
	datacenter := keySplit[1]

	client := analyzers.NewAnalyzeClient(cfg)
	req, err := http.NewRequest("GET", fmt.Sprintf(BASE_URL, datacenter)+"/verified-domains", nil)
	if err != nil {
		color.Red("[x] Error: %s", err)
		return domains, err
	}

	req.SetBasicAuth("anystring", key)
	resp, err := client.Do(req)
	if err != nil {
		color.Red("[x] Error: %s", err)
		return domains, err
	}

	defer resp.Body.Close()

	if err := json.NewDecoder(resp.Body).Decode(&domains); err != nil {
		color.Red("[x] Error: %s", err)
		return domains, err
	}

	return domains, nil
}

func AnalyzePermissions(cfg *config.Config, key string) {
	// get metadata
	metadata, err := getMetadata(cfg, key)
	if err != nil {
		color.Red("[x] Error: %s", err)
		return
	}

	// print mailchimp instance metadata
	if metadata.AccountID == "" {
		color.Red("[x] Invalid Mailchimp API key")
		return
	}
	printMetadata(metadata)

	// print full api key permissions
	color.Green("\n[i] Permissions: Full Access\n\n")

	// get sending domains
	domains, err := getDomains(cfg, key)
	if err != nil {
		color.Red("[x] Error: %s", err)
		return
	}

	// print sending domains
	if len(domains.Domains) > 0 {
		printDomains(domains)
	} else {
		color.Yellow("[i] No sending domains found\n")
	}

}

func printMetadata(metadata MetadataJSON) {
	color.Green("[!] Valid Mailchimp API key\n\n")

	// print table with account info
	color.Yellow("[i] Mailchimp Account Info:\n")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendRow([]interface{}{("Account Name"), color.GreenString("%s", metadata.AccountName)})
	t.AppendRow([]interface{}{("Company Name"), color.GreenString("%s", metadata.Contact.Company)})
	t.AppendRow([]interface{}{("Address"), color.GreenString("%s %s\n%s, %s %s\n%s", metadata.Contact.Address1, metadata.Contact.Address2, metadata.Contact.City, metadata.Contact.State, metadata.Contact.Zip, metadata.Contact.Country)})
	t.AppendRow([]interface{}{("Total Subscribers"), color.GreenString("%d", metadata.TotalSubscribers)})
	t.Render()

	// print user info
	color.Yellow("\n[i] Mailchimp User Info:\n")
	t = table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendRow([]interface{}{("User Name"), color.GreenString("%s %s", metadata.FirstName, metadata.LastName)})
	t.AppendRow([]interface{}{("User Email"), color.GreenString("%s", metadata.Email)})
	t.AppendRow([]interface{}{("User Role"), color.GreenString("%s", metadata.Role)})
	t.AppendRow([]interface{}{("Last Login"), color.GreenString("%s", metadata.LastLogin)})
	t.AppendRow([]interface{}{("Member Since"), color.GreenString("%s", metadata.MemberSince)})
	t.Render()
}

func printDomains(domains DomainsJSON) {
	color.Yellow("\n[i] Sending Domains:\n")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Domain", "Enabled and Verified"})
	for _, domain := range domains.Domains {
		authenticated := ""
		if domain.Authenticated && domain.Verified {
			authenticated = color.GreenString("Yes")
		} else {
			authenticated = color.RedString("No")
		}
		t.AppendRow([]interface{}{color.GreenString(domain.Domain), authenticated})
	}
	t.Render()
}
