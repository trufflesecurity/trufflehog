package mailchimp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/table"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/pb/analyzerpb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/pb/resourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

const BASE_URL = "https://%s.api.mailchimp.com/3.0"

var _ analyzers.Analyzer = (*Analyzer)(nil)

type Analyzer struct {
	Cfg *config.Config
}

func (Analyzer) Type() analyzerpb.SecretType { return analyzerpb.SecretType_MAILCHIMP }

func (a Analyzer) Analyze(_ context.Context, key string, _ map[string]string) (*analyzers.AnalyzerResult, error) {
	info, err := AnalyzePermissions(a.Cfg, key)
	if err != nil {
		return nil, err
	}
	return secretInfoToAnalyzerResult(info), nil
}

func secretInfoToAnalyzerResult(info *SecretInfo) *analyzers.AnalyzerResult {
	if info == nil {
		return nil
	}

	// Metadata
	//	AccountID
	//	AccountName
	//	Email
	//	FirstName
	//	LastName
	//	Role
	//	MemberSince
	//	PricingPlan
	//	AccountTimezone
	//	Contact
	//		Company
	//		Address1
	//		Address2
	//		City
	//		State
	//		Zip
	//		Country
	//	LastLogin
	//	TotalSubscribers
	// Domains
	//	Domains
	//		Domain        string
	//		Authenticated bool
	//		Verified      bool
	//	}

	result := analyzers.AnalyzerResult{
		SecretMetadata: map[string]string{
			// Metadata info.
			"account_name": info.Metadata.AccountName,
			"company_name": info.Metadata.Contact.Company,
			"address": fmt.Sprintf("%s %s\n%s, %s %s\n%s",
				info.Metadata.Contact.Address1, info.Metadata.Contact.Address2,
				info.Metadata.Contact.City, info.Metadata.Contact.State, info.Metadata.Contact.Zip,
				info.Metadata.Contact.Country,
			),
			"total_subscribers": strconv.Itoa(info.Metadata.TotalSubscribers),
			// User info.
			"user_name":    fmt.Sprintf("%s %s", info.Metadata.FirstName, info.Metadata.LastName),
			"user_email":   info.Metadata.Email,
			"user_role":    info.Metadata.Role,
			"last_login":   info.Metadata.LastLogin,
			"member_since": info.Metadata.MemberSince,
		},
	}

	for _, domain := range info.Domains.Domains {
		rp := analyzers.ResourcePermission{
			ResourceTree: analyzers.ResourceTree{
				Resource: &resourcespb.Resource{
					SecretType:   analyzerpb.SecretType_MAILCHIMP,
					ResourceType: resourcespb.ResourceType_DOMAIN,
					Name:         domain.Domain,
					Metadata:     map[string]string{},
				},
			},
			Permissions: convertDomainPermissions(domain),
		}

		result.ResourcePermissions = append(result.ResourcePermissions, rp)
	}

	return &result
}

func convertDomainPermissions(domain Domain) []analyzers.Permission {
	var permissions []analyzers.Permission
	if domain.Authenticated {
		permissions = append(permissions, analyzers.Permission("authenticated"))
	}
	if domain.Verified {
		permissions = append(permissions, analyzers.Permission("verified"))
	}
	return permissions
}

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
	Domains []Domain `json:"domains"`
}

type Domain struct {
	Domain        string `json:"domain"`
	Authenticated bool   `json:"authenticated"`
	Verified      bool   `json:"verified"`
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
		return metadata, err
	}

	req.SetBasicAuth("anystring", key)
	resp, err := client.Do(req)
	if err != nil {
		return metadata, err
	}

	defer resp.Body.Close()

	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
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
		return domains, err
	}

	req.SetBasicAuth("anystring", key)
	resp, err := client.Do(req)
	if err != nil {
		return domains, err
	}

	defer resp.Body.Close()

	if err := json.NewDecoder(resp.Body).Decode(&domains); err != nil {
		return domains, err
	}

	return domains, nil
}

type SecretInfo struct {
	Metadata MetadataJSON
	Domains  DomainsJSON
}

func AnalyzePermissions(cfg *config.Config, key string) (*SecretInfo, error) {
	// get metadata
	metadata, err := getMetadata(cfg, key)
	if err != nil {
		return nil, err
	}
	if metadata.AccountID == "" {
		return nil, fmt.Errorf("Invalid Mailchimp API key")
	}

	// get sending domains
	domains, err := getDomains(cfg, key)
	if err != nil {
		return nil, err
	}

	return &SecretInfo{
		Metadata: metadata,
		Domains:  domains,
	}, nil
}

func AnalyzeAndPrintPermissions(cfg *config.Config, key string) {
	info, err := AnalyzePermissions(cfg, key)
	if err != nil {
		color.Red("[x] Error: %s", err.Error())
		return
	}

	printMetadata(info.Metadata)

	// print full api key permissions
	color.Green("\n[i] Permissions: Full Access\n\n")

	// print sending domains
	if len(info.Domains.Domains) > 0 {
		printDomains(info.Domains)
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
	t.AppendRow([]any{("Account Name"), color.GreenString("%s", metadata.AccountName)})
	t.AppendRow([]any{("Company Name"), color.GreenString("%s", metadata.Contact.Company)})
	t.AppendRow([]any{("Address"), color.GreenString("%s %s\n%s, %s %s\n%s", metadata.Contact.Address1, metadata.Contact.Address2, metadata.Contact.City, metadata.Contact.State, metadata.Contact.Zip, metadata.Contact.Country)})
	t.AppendRow([]any{("Total Subscribers"), color.GreenString("%d", metadata.TotalSubscribers)})
	t.Render()

	// print user info
	color.Yellow("\n[i] Mailchimp User Info:\n")
	t = table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendRow([]any{("User Name"), color.GreenString("%s %s", metadata.FirstName, metadata.LastName)})
	t.AppendRow([]any{("User Email"), color.GreenString("%s", metadata.Email)})
	t.AppendRow([]any{("User Role"), color.GreenString("%s", metadata.Role)})
	t.AppendRow([]any{("Last Login"), color.GreenString("%s", metadata.LastLogin)})
	t.AppendRow([]any{("Member Since"), color.GreenString("%s", metadata.MemberSince)})
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
		t.AppendRow([]any{color.GreenString(domain.Domain), authenticated})
	}
	t.Render()
}
