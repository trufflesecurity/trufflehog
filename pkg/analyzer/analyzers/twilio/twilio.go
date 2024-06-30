package twilio

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/fatih/color"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
)

type VerifyJSON struct {
	Code int `json:"code"`
}

const (
	AUTHENTICATED_NO_PERMISSION = 70051
	INVALID_CREDENTIALS         = 20003
)

// splitKey splits the key into SID and Secret
func splitKey(key string) (string, string, error) {
	split := strings.Split(key, ":")
	if len(split) != 2 {
		return "", "", errors.New("key must be in the format SID:Secret")
	}
	return split[0], split[1], nil
}

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

	// add query params
	q := req.URL.Query()
	q.Add("FriendlyName", "zpoOnD08HdLLZGFnGUMTxbX3qQ1kS")
	req.URL.RawQuery = q.Encode()

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

// getVerifyServicesStatusCode returns the status code and the JSON response from the Verify Services endpoint
// only the code value is captured in the JSON response and this is only shown when the key is invalid or has no permissions
func getVerifyServicesStatusCode(cfg *config.Config, sid string, secret string) (VerifyJSON, error) {
	var verifyJSON VerifyJSON

	// create http client
	client := analyzers.NewAnalyzeClient(cfg)

	// create request
	req, err := http.NewRequest("GET", "https://verify.twilio.com/v2/Services", nil)
	if err != nil {
		return verifyJSON, err
	}

	// add query params
	q := req.URL.Query()
	q.Add("FriendlyName", "zpoOnD08HdLLZGFnGUMTxbX3qQ1kS")
	req.URL.RawQuery = q.Encode()

	// add basicAuth
	req.SetBasicAuth(sid, secret)

	// send request
	resp, err := client.Do(req)
	if err != nil {
		return verifyJSON, err
	}
	defer resp.Body.Close()

	// read response
	if err := json.NewDecoder(resp.Body).Decode(&verifyJSON); err != nil {
		return verifyJSON, err
	}

	return verifyJSON, nil
}

func AnalyzePermissions(cfg *config.Config, key string) {
	sid, secret, err := splitKey(key)
	if err != nil {
		color.Red("[x]" + err.Error())
		return
	}

	verifyJSON, err := getVerifyServicesStatusCode(cfg, sid, secret)
	if err != nil {
		color.Red("[x]" + err.Error())
		return
	}

	if verifyJSON.Code == INVALID_CREDENTIALS {
		color.Red("[x] Invalid Twilio API Key")
		return
	}

	if verifyJSON.Code == AUTHENTICATED_NO_PERMISSION {
		printRestrictedKeyMsg()
		return
	}

	statusCode, err := getAccountsStatusCode(cfg, sid, secret)
	if err != nil {
		color.Red("[x]" + err.Error())
		return
	}
	printPermissions(statusCode)
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
