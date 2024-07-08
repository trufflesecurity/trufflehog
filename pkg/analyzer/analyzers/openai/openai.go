package openai

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/table"

	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
)

const (
	BASE_URL      = "https://api.openai.com"
	ORGS_ENDPOINT = "/v1/organizations"
	ME_ENDPOINT   = "/v1/me"
)

type MeJSON struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Email      string `json:"email"`
	Phone      string `json:"phone_number"`
	MfaEnabled bool   `json:"mfa_flag_enabled"`
	Orgs       struct {
		Data []struct {
			Title string `json:"title"`
		} `json:"data"`
	} `json:"orgs"`
}

var POST_PAYLOAD = map[string]interface{}{"speed": 1}

// AnalyzePermissions will analyze the permissions of an OpenAI API key
func AnalyzePermissions(cfg *config.Config, key string) {
	if meJSON, err := getUserData(cfg, key); err != nil {
		color.Red("[x]" + err.Error())
		return
	} else {
		printUserData(meJSON)
	}

	if isAdmin, err := checkAdminKey(cfg, key); isAdmin {
		color.Green("[!] Admin API Key. All permissions available.")
		return
	} else if err != nil {
		color.Red("[x]" + err.Error())
		return
	} else {
		color.Yellow("[!] Restricted API Key. Limited permissions available.")
		if err := analyzeScopes(key); err != nil {
			color.Red("[x]" + err.Error())
			return
		}
		printPermissions(cfg.ShowAll)
	}

}

func analyzeScopes(key string) error {
	for _, scope := range SCOPES {
		if err := scope.RunTests(key); err != nil {
			return err
		}
	}
	return nil
}

func openAIRequest(cfg *config.Config, method string, url string, key string, data map[string]interface{}) ([]byte, *http.Response, error) {
	var inBody io.Reader
	if data != nil {
		jsonData, err := json.Marshal(data)
		if err != nil {
			return nil, nil, err
		}
		inBody = bytes.NewBuffer(jsonData)
	}

	client := analyzers.NewAnalyzeClient(cfg)
	req, err := http.NewRequest(method, url, inBody)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Add("Authorization", "Bearer "+key)
	req.Header.Add("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}

	defer resp.Body.Close()

	outBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}

	return outBody, resp, nil
}

func checkAdminKey(cfg *config.Config, key string) (bool, error) {
	// Check for all permissions
	//nolint:bodyclose
	_, resp, err := openAIRequest(cfg, "GET", BASE_URL+ORGS_ENDPOINT, key, nil)
	if err != nil {
		return false, err
	}
	switch resp.StatusCode {
	case 200:
		return true, nil
	case 403:
		return false, nil
	default:
		return false, err
	}
}

func getUserData(cfg *config.Config, key string) (MeJSON, error) {
	var meJSON MeJSON
	//nolint:bodyclose
	me, resp, err := openAIRequest(cfg, "GET", BASE_URL+ME_ENDPOINT, key, nil)
	if err != nil {
		return meJSON, err
	}

	if resp.StatusCode != 200 {
		return meJSON, fmt.Errorf("Invalid OpenAI Token")
	}
	color.Green("[!] Valid OpenAI Token\n\n")

	// Marshall me into meJSON struct
	if err := json.Unmarshal(me, &meJSON); err != nil {
		return meJSON, err
	}
	return meJSON, nil
}

func printUserData(meJSON MeJSON) {
	color.Green("[i] User: %v", meJSON.Name)
	color.Green("[i] Email: %v", meJSON.Email)
	color.Green("[i] Phone: %v", meJSON.Phone)
	color.Green("[i] MFA Enabled: %v", meJSON.MfaEnabled)

	if len(meJSON.Orgs.Data) > 0 {
		color.Green("[i] Organizations:")
		for _, org := range meJSON.Orgs.Data {
			color.Green("  - %v", org.Title)
		}
	}
	fmt.Print("\n\n")
}

func stringifyPermissionStatus(tests []analyzers.HttpStatusTest) analyzers.PermissionType {
	readStatus := false
	writeStatus := false
	errors := false
	for _, test := range tests {
		if test.Type == analyzers.READ {
			readStatus = test.Status.Value
		} else if test.Type == analyzers.WRITE {
			writeStatus = test.Status.Value
		}
		if test.Status.IsError {
			errors = true
		}
	}
	if errors {
		return analyzers.ERROR
	}
	if readStatus && writeStatus {
		return analyzers.READ_WRITE
	} else if readStatus {
		return analyzers.READ
	} else if writeStatus {
		return analyzers.WRITE
	} else {
		return analyzers.NONE
	}
}

func printPermissions(show_all bool) {
	fmt.Print("\n\n")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Scope", "Endpoints", "Permission"})

	for _, scope := range SCOPES {
		status := stringifyPermissionStatus(scope.Tests)
		writer := analyzers.GetWriterFromStatus(status)
		if show_all || status != analyzers.NONE {
			t.AppendRow([]interface{}{writer(scope.Name), writer(scope.Endpoints[0]), writer(status)})
			for i := 1; i < len(scope.Endpoints); i++ {
				t.AppendRow([]interface{}{"", writer(scope.Endpoints[i]), writer(status)})
			}
		}
	}
	t.Render()
	fmt.Print("\n\n")
}
