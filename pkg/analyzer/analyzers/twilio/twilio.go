//go:generate generate_permissions permissions.yaml permissions.go twilio

package twilio

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/fatih/color"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

type Analyzer struct {
	Cfg *config.Config
}

func (a *Analyzer) Type() analyzers.AnalyzerType {
	return analyzers.AnalyzerTypeTwilio
}

func (a *Analyzer) Analyze(ctx context.Context, credentialInfo map[string]string) (*analyzers.AnalyzerResult, error) {
	key, ok := credentialInfo["key"]
	if !ok {
		return nil, analyzers.NewAnalysisError("Twilio", "validate_credentials", "config", "", errors.New("key not found in credentialInfo"))
	}

	sid, ok := credentialInfo["sid"]
	if !ok {
		return nil, analyzers.NewAnalysisError("Twilio", "validate_credentials", "config", "", errors.New("sid not found in credentialInfo"))
	}

	if a.Cfg == nil {
		a.Cfg = &config.Config{} // You might need to adjust this based on how you want to handle config
	}

	info, err := AnalyzePermissions(a.Cfg, sid, key)
	if err != nil {
		return nil, analyzers.NewAnalysisError("Twilio", "analyze_permissions", "API", "", err)
	}

	// List parent and subaccounts
	accounts, err := listTwilioAccounts(a.Cfg, sid, key)
	if err != nil {
		return nil, analyzers.NewAnalysisError("Twilio", "analyze_permissions", "API", "", err)
	}

	var permissions []Permission
	if info.AccountStatusCode == 200 {
		permissions = []Permission{
			AccountManagementRead,
			AccountManagementWrite,
			SubaccountConfigurationRead,
			SubaccountConfigurationWrite,
			KeyManagementRead,
			KeyManagementWrite,
			ServiceVerificationRead,
			ServiceVerificationWrite,
			SmsRead,
			SmsWrite,
			VoiceRead,
			VoiceWrite,
			MessagingRead,
			MessagingWrite,
			CallManagementRead,
			CallManagementWrite,
		}
	} else if info.AccountStatusCode == 401 {
		permissions = []Permission{
			ServiceVerificationRead,
			ServiceVerificationWrite,
			SmsRead,
			SmsWrite,
			VoiceRead,
			VoiceWrite,
			MessagingRead,
			MessagingWrite,
			CallManagementRead,
			CallManagementWrite,
		}
	}

	var (
		bindings                  []analyzers.Binding
		parentAccountSID          = ""
		parentAccountFriendlyName = ""
	)

	if len(info.ServicesRes.Services) > 0 {
		parentAccountSID = info.ServicesRes.Services[0].AccountSID
		parentAccountFriendlyName = info.ServicesRes.Services[0].FriendlyName
	}

	for _, account := range accounts {
		accountType := "Account"
		if parentAccountSID != "" && account.SID != parentAccountSID {
			accountType = "SubAccount"
		}
		resource := analyzers.Resource{
			Name:               account.FriendlyName,
			FullyQualifiedName: "twilio.com/account/" + account.SID,
			Type:               accountType,
		}
		if parentAccountSID != "" && account.SID != parentAccountSID {
			resource.Parent = &analyzers.Resource{
				Name:               parentAccountFriendlyName,
				FullyQualifiedName: "twilio.com/account/" + parentAccountSID,
				Type:               "Account",
			}
		}

		for _, perm := range permissions {
			permStr, _ := perm.ToString()
			bindings = append(bindings, analyzers.Binding{
				Resource: resource,
				Permission: analyzers.Permission{
					Value: permStr,
				},
			})
		}
	}

	return &analyzers.AnalyzerResult{
		AnalyzerType: analyzers.AnalyzerTypeTwilio,
		Bindings:     bindings,
	}, nil
}

type secretInfo struct {
	ServicesRes       serviceResponse
	AccountStatusCode int
}

const (
	AUTHENTICATED_NO_PERMISSION = 70051
	INVALID_CREDENTIALS         = 20003
)

// getAccountsStatusCode returns the status code from the Accounts endpoint
// this is used to determine whether the key is scoped as main or standard, since standard has no access here.
func getAccountsStatusCode(cfg *config.Config, sid string, secret string) (int, error) {
	// create http client
	client := analyzers.NewAnalyzeClient(cfg)

	// create request
	req, err := http.NewRequest("GET", "https://api.twilio.com/2010-04-01/Accounts", nil)
	if err != nil {
		return 0, err
	}

	// add basicAuth
	req.SetBasicAuth(sid, secret)

	// send request
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	return resp.StatusCode, nil
}

type serviceResponse struct {
	Code     int       `json:"code"`
	Services []service `json:"services"`
}

type service struct {
	FriendlyName string `json:"friendly_name"` // friendly name of a service
	SID          string `json:"sid"`           // object id of service
	AccountSID   string `json:"account_sid"`   // account sid
}

// getVerifyServicesStatusCode returns the status code and the JSON response from the Verify Services endpoint
// only the code value is captured in the JSON response and this is only shown when the key is invalid or has no permissions
func getVerifyServicesStatusCode(cfg *config.Config, sid string, secret string) (serviceResponse, error) {
	var serviceRes serviceResponse

	// create http client
	client := analyzers.NewAnalyzeClient(cfg)

	// create request
	req, err := http.NewRequest("GET", "https://verify.twilio.com/v2/Services", nil)
	if err != nil {
		return serviceRes, err
	}

	// add basicAuth
	req.SetBasicAuth(sid, secret)

	// send request
	resp, err := client.Do(req)
	if err != nil {
		return serviceRes, err
	}
	defer resp.Body.Close()

	// read response
	if err := json.NewDecoder(resp.Body).Decode(&serviceRes); err != nil {
		return serviceRes, err
	}

	return serviceRes, nil
}

func listTwilioAccounts(cfg *config.Config, sid, secret string) ([]service, error) {
	// create http client
	client := analyzers.NewAnalyzeClient(cfg)

	// create request
	req, err := http.NewRequest("GET", "https://api.twilio.com/2010-04-01/Accounts.json", nil)
	if err != nil {
		return nil, err
	}

	// add basicAuth
	req.SetBasicAuth(sid, secret)

	// send request
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Accounts []service `json:"accounts"`
	}

	// read response
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result.Accounts, nil
}

func AnalyzePermissions(cfg *config.Config, sid, secret string) (*secretInfo, error) {
	servicesRes, err := getVerifyServicesStatusCode(cfg, sid, secret)
	if err != nil {
		return nil, err
	}

	statusCode, err := getAccountsStatusCode(cfg, sid, secret)
	if err != nil {
		return nil, err
	}

	return &secretInfo{
		ServicesRes:       servicesRes,
		AccountStatusCode: statusCode,
	}, nil
}

func AnalyzeAndPrintPermissions(cfg *config.Config, sid, secret string) {
	info, err := AnalyzePermissions(cfg, sid, secret)
	if err != nil {
		color.Red("[x] Error: %s", err.Error())
		return
	}

	if info.ServicesRes.Code == INVALID_CREDENTIALS {
		color.Red("[x] Invalid Twilio API Key")
		return
	}

	if info.ServicesRes.Code == AUTHENTICATED_NO_PERMISSION {
		printRestrictedKeyMsg()
		return
	}

	printPermissions(info.AccountStatusCode)
}

// printPermissions prints the permissions based on the status code
// 200 means the key is main, 401 means the key is standard
func printPermissions(statusCode int) {

	if statusCode != 200 && statusCode != 401 {
		color.Red("[x] Invalid Twilio API Key")
		return
	}

	color.Green("[!] Valid Twilio API Key\n")
	color.Green("[i] Expires: Never")

	if statusCode == 401 {
		color.Yellow("[i] Key type: Standard")
		color.Yellow("[i] Permissions: All EXCEPT key management and account/subaccount configuration.")

	} else if statusCode == 200 {
		color.Green("[i] Key type: Main (aka Admin)")
		color.Green("[i] Permissions: All")
	}
}

// printRestrictedKeyMsg prints the message for a restricted key
// this is a temporary measure since the restricted key type is still in beta
func printRestrictedKeyMsg() {
	color.Green("[!] Valid Twilio API Key\n")
	color.Green("[i] Expires: Never")
	color.Yellow("[i] Key type: Restricted")
	color.Yellow("[i] Permissions: Limited")
	fmt.Println("[*] Note: Twilio is rolling out a Restricted API Key type, which provides fine-grained control over API endpoints. Since it's still in a Public Beta, this has not been incorporated into this tool.")
}
