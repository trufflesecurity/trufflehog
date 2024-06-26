package sourcegraph

// ToDo: Add suport for custom domain

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/fatih/color"
)

type GraphQLError struct {
	Message string   `json:"message"`
	Path    []string `json:"path"`
}

type GraphQLResponse struct {
	Errors []GraphQLError `json:"errors"`
	Data   interface{}    `json:"data"`
}

type UserInfoJSON struct {
	Data struct {
		CurrentUser struct {
			Username  string `json:"username"`
			Email     string `json:"email"`
			SiteAdmin bool   `json:"siteAdmin"`
			CreatedAt string `json:"createdAt"`
		} `json:"currentUser"`
	} `json:"data"`
}

func getUserInfo(key string) (UserInfoJSON, error) {
	var userInfo UserInfoJSON

	client := &http.Client{}
	payload := "{\"query\":\"query { currentUser { username, email, siteAdmin, createdAt } }\"}"
	req, err := http.NewRequest("POST", "https://sourcegraph.com/.api/graphql", strings.NewReader(payload))
	if err != nil {
		return userInfo, err
	}

	req.Header.Set("Authorization", "token "+key)

	resp, err := client.Do(req)
	if err != nil {
		return userInfo, err
	}

	defer resp.Body.Close()

	err = json.NewDecoder(resp.Body).Decode(&userInfo)
	if err != nil {
		return userInfo, err
	}
	return userInfo, nil
}

func checkSiteAdmin(key string) (bool, error) {
	query := `
	{
	    "query": "query webhooks($first: Int, $after: String, $kind: ExternalServiceKind) { webhooks(first: $first, after: $after, kind: $kind) { totalCount } }",
	    "variables": {
	        "first": 10,
	        "after": "",
	        "kind": "GITHUB"
	    }
	}`

	client := &http.Client{}
	req, err := http.NewRequest("POST", "https://sourcegraph.com/.api/graphql", strings.NewReader(query))
	if err != nil {
		return false, err
	}

	req.Header.Set("Authorization", "token "+key)

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}

	defer resp.Body.Close()

	var response GraphQLResponse

	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		return false, err
	}

	if len(response.Errors) > 0 {
		return false, nil
	}
	return true, nil
}

func AnalyzePermissions(key string, showAll bool) {

	userInfo, err := getUserInfo(key)
	if err != nil {
		color.Red("Error: %s", err)
		return
	}

	// second call
	userInfo, err = getUserInfo(key)
	if err != nil {
		color.Red("Error: %s", err)
		return
	}

	if userInfo.Data.CurrentUser.Username == "" {
		color.Red("[x] Invalid Sourcegraph Access Token")
		return
	}
	color.Green("[!] Valid Sourcegraph Access Token\n\n")
	color.Yellow("[i] Sourcegraph User Information\n")
	color.Green("Username: %s\n", userInfo.Data.CurrentUser.Username)
	color.Green("Email: %s\n", userInfo.Data.CurrentUser.Email)
	color.Green("Created At: %s\n\n", userInfo.Data.CurrentUser.CreatedAt)

	isSiteAdmin, err := checkSiteAdmin(key)
	if err != nil {
		color.Red("Error: %s", err)
		return
	}

	if isSiteAdmin {
		color.Green("[!] Token Permissions: Site Admin")
	} else {
		// This is the default for all access tokens as of 6/11/24
		color.Yellow("[i] Token Permissions: user:full (default)")
	}

}
