package jira

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
)

type endpoint int

const (
	// list of endpoints
	mySelf endpoint = iota
	myPermissions
	getAllProjects
	searchIssues
	getAllBoards
	getAllUsers
)

var (
	baseURL = "https://%s/rest"

	// endpoints contain Jira API endpoints
	endpoints = map[endpoint]string{
		mySelf:         "myself",
		myPermissions:  "mypermissions",
		searchIssues:   "search/jql",
		getAllProjects: "project/search",
		getAllBoards:   "board",
		getAllUsers:    "users/search",
	}
)

// buildBasicAuthHeader constructs the Basic Auth header
func buildBasicAuthHeader(email, token string) string {
	auth := fmt.Sprintf("%s:%s", email, token)
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
}

// makeJiraRequest send the API request to passed url with passed key as API Key and return response body and status code
func makeJiraRequest(client *http.Client, endpoint, email, token string) ([]byte, int, error) {
	// create request
	req, err := http.NewRequest(http.MethodGet, endpoint, http.NoBody)
	if err != nil {
		return nil, 0, err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", buildBasicAuthHeader(email, token))

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}

	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	responseBodyByte, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, err
	}

	return responseBodyByte, resp.StatusCode, nil
}

func checkAllJiraPermissions(client *http.Client, domain, email, token string) ([]byte, int, error) {
	var allPermissions []string
	for _, key := range PermissionStrings {
		allPermissions = append(allPermissions, strings.ToUpper(key))
	}

	query := url.Values{}
	query.Set("permissions", strings.Join(allPermissions, ","))

	endpoint := fmt.Sprintf("%s/api/3/%s?%s", fmt.Sprintf(baseURL, domain), endpoints[myPermissions], query.Encode())

	return makeJiraRequest(client, endpoint, email, token)
}

// captureResources try to capture all the resource that the key can access
func captureResources(client *http.Client, domain, email, token string, secretInfo *SecretInfo) error {
	var (
		wg             sync.WaitGroup
		errAggWg       sync.WaitGroup
		aggregatedErrs = make([]error, 0)
		errChan        = make(chan error, 1)
	)

	errAggWg.Add(1)
	go func() {
		defer errAggWg.Done()
		for err := range errChan {
			aggregatedErrs = append(aggregatedErrs, err)
		}
	}()

	// helper to launch tasks concurrently.
	launchTask := func(task func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := task(); err != nil {
				errChan <- err
			}
		}()
	}

	launchTask(func() error {
		return captureProjects(client, domain, email, token, secretInfo)
	})
	launchTask(func() error { return captureBoards(client, domain, email, token, secretInfo) })
	launchTask(func() error { return captureUsers(client, domain, email, token, secretInfo) })

	wg.Wait()
	close(errChan)
	errAggWg.Wait()

	if len(aggregatedErrs) > 0 {
		return errors.Join(aggregatedErrs...)
	}

	return nil
}

// captureTokenInfo calls `/tokens/self` API and capture the token information in secretInfo
func captureTokenInfo(client *http.Client, token, domain, email string, secretInfo *SecretInfo) error {
	respBody, statusCode, err := makeJiraRequest(client, fmt.Sprintf(baseURL, domain)+endpoints[mySelf], email, token)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var token SelfToken

		if err := json.Unmarshal(respBody, &token); err != nil {
			return err
		}

		if token.ExpiresAt == "" {
			token.ExpiresAt = "never"
		}

		// secretInfo.TokenInfo = token

		return nil
	case http.StatusUnauthorized:
		return fmt.Errorf("invalid/expired api key")
	default:
		return fmt.Errorf("unexpected status code: %d for API: %s", statusCode, endpoints[mySelf])
	}
}

// captureUserInfo calls `/myself` API and store the current user information in secretInfo
func captureUserInfo(client *http.Client, token, domain, email string, secretInfo *SecretInfo) (int, error) {
	endPoint := fmt.Sprintf("%s/api/3/%s", fmt.Sprintf(baseURL, domain), endpoints[mySelf])
	respBody, statusCode, err := makeJiraRequest(client, endPoint, email, token)
	if err != nil {
		return statusCode, err
	}

	switch statusCode {
	case http.StatusOK:
		var user JiraUser

		if err := json.Unmarshal(respBody, &user); err != nil {
			return statusCode, err
		}

		secretInfo.UserInfo = user
		return statusCode, nil
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
		return statusCode, nil
	default:
		return statusCode, fmt.Errorf("unexpected status code: %d for API: %s", statusCode, endpoints[mySelf])
	}
}

func captureProjects(client *http.Client, domain, email, token string, secretInfo *SecretInfo) error {
	endpoint := fmt.Sprintf("%s/api/3/%s", fmt.Sprintf(baseURL, domain), endpoints[getAllProjects])
	body, statusCode, err := makeJiraRequest(client, endpoint, email, token)
	if err != nil {
		return err
	}

	if statusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d for API: %s", statusCode, endpoints[getAllProjects])
	}

	var resp ProjectSearchResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return fmt.Errorf("failed to unmarshal project response: %w", err)
	}

	for _, proj := range resp.Values {
		resource := JiraResource{
			ID:   proj.ID,
			Name: proj.Name,
			Type: ResourceTypeProject,
			Metadata: map[string]string{
				"Key":     proj.Key,
				"UUID":    proj.UUID,
				"Private": strconv.FormatBool(proj.IsPrivate),
				"TypeKey": proj.ProjectTypeKey,
			},
		}
		secretInfo.appendResource(resource)

		// Fetch issues for the project
		if err := captureIssues(client, domain, email, token, proj.Key, secretInfo); err != nil {
			return fmt.Errorf("failed to capture issues for project %s: %w", proj.Key, err)
		}
	}

	return nil
}

func captureIssues(client *http.Client, domain, email, token, projectKey string, secretInfo *SecretInfo) error {
	path := fmt.Sprintf("api/3/%s", endpoints[searchIssues])
	query := fmt.Sprintf("jql=project=%s&fields=issuetype,summary,status", projectKey)
	endpoint := fmt.Sprintf("%s/%s?%s", fmt.Sprintf(baseURL, domain), path, query)

	body, statusCode, err := makeJiraRequest(client, endpoint, email, token)
	if err != nil {
		return err
	}

	if statusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d for API: %s", statusCode, endpoint)
	}

	var issueResp JiraIssue
	if err := json.Unmarshal(body, &issueResp); err != nil {
		return fmt.Errorf("failed to unmarshal issue response: %w", err)
	}

	for _, issue := range issueResp.Issues {
		issueResource := JiraResource{
			ID:   issue.ID,
			Name: issue.Key,
			Type: issue.Fields.IssueType.Name,
			Metadata: map[string]string{
				"Summary": issue.Fields.Summary,
				"Status":  issue.Fields.Status.Name,
				"Project": projectKey,
			},
		}
		secretInfo.appendResource(issueResource)
	}

	return nil
}

func captureBoards(client *http.Client, domain, email, token string, secretInfo *SecretInfo) error {
	endpoint := fmt.Sprintf("%s/agile/1.0/%s", fmt.Sprintf(baseURL, domain), endpoints[getAllBoards])

	body, statusCode, err := makeJiraRequest(client, endpoint, email, token)
	if err != nil {
		return err
	}

	if statusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d for API: %s", statusCode, endpoint)
	}

	var boardResp JiraBoard
	if err := json.Unmarshal(body, &boardResp); err != nil {
		return fmt.Errorf("failed to unmarshal board response: %w", err)
	}

	for _, board := range boardResp.Values {
		boardResource := JiraResource{
			ID:   fmt.Sprintf("%d", board.ID),
			Name: board.Name,
			Type: ResourceTypeBoard,
			Metadata: map[string]string{
				"BoardType":    board.Type,
				"IsPrivate":    strconv.FormatBool(board.IsPrivate),
				"ProjectID":    fmt.Sprintf("%d", board.Location.ProjectID),
				"ProjectKey":   board.Location.ProjectKey,
				"ProjectName":  board.Location.ProjectName,
				"ProjectType":  board.Location.ProjectTypeKey,
				"DisplayName":  board.Location.DisplayName,
				"AvatarURI":    board.Location.AvatarURI,
				"BoardSelfURL": board.Self,
			},
		}
		secretInfo.appendResource(boardResource)
	}

	return nil
}

func captureUsers(client *http.Client, domain, email, token string, secretInfo *SecretInfo) error {
	endpoint := fmt.Sprintf("%s/api/3/%s", fmt.Sprintf(baseURL, domain), endpoints[getAllUsers])

	body, statusCode, err := makeJiraRequest(client, endpoint, email, token)
	if err != nil {
		return err
	}

	if statusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d for API: %s", statusCode, endpoint)
	}

	var users []struct {
		AccountID    string `json:"accountId"`
		DisplayName  string `json:"displayName"`
		Active       bool   `json:"active"`
		EmailAddress string `json:"emailAddress"`
		AccountType  string `json:"accountType"`
		Self         string `json:"self"`
	}

	if err := json.Unmarshal(body, &users); err != nil {
		return fmt.Errorf("failed to unmarshal user response: %w", err)
	}

	for _, user := range users {
		userResource := JiraResource{
			ID:   user.AccountID,
			Name: user.DisplayName,
			Type: "User",
			Metadata: map[string]string{
				"Email":       user.EmailAddress,
				"AccountType": user.AccountType,
				"Active":      strconv.FormatBool(user.Active),
				"SelfURL":     user.Self,
			},
		}
		if user.AccountType != "app" {
			secretInfo.appendResource(userResource)
		}

	}

	return nil
}
