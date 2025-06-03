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
	findGroups
	getAuditRecords
)

var (
	baseURL = "https://%s/rest"

	// endpoints contain Jira API endpoints
	endpoints = map[endpoint]string{
		mySelf:          "myself",
		myPermissions:   "mypermissions",
		searchIssues:    "search/jql",
		getAllProjects:  "project/search",
		getAllBoards:    "board",
		getAllUsers:     "users/search",
		findGroups:      "groups/picker",
		getAuditRecords: "auditing/record",
	}

	userPerms = make(map[Permission]bool)
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

func capturePermissions(client *http.Client, domain, email, token string) ([]byte, int, error) {
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
func captureResources(client *http.Client, domain, email, token string, secretInfo *SecretInfo, grantedPermissions []string) error {
	for _, p := range grantedPermissions {
		userPerms[StringToPermission[strings.ToLower(p)]] = true
	}

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

	launchTask := func(task func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := task(); err != nil {
				errChan <- err
			}
		}()
	}

	projects, err := captureProjects(client, domain, email, token, secretInfo)
	if err != nil {
		return fmt.Errorf("failed to capture projects: %w", err)
	}
	if projects != nil {
		for _, proj := range projects.Values {
			launchTask(func() error {
				return captureIssues(client, domain, email, token, proj.Key, secretInfo)
			})
		}
	}
	launchTask(func() error { return captureBoards(client, domain, email, token, secretInfo) })
	launchTask(func() error { return captureUsers(client, domain, email, token, secretInfo) })
	launchTask(func() error { return captureGroups(client, domain, email, token, secretInfo) })
	launchTask(func() error { return captureAuditLogs(client, domain, email, token, secretInfo) })

	wg.Wait()
	close(errChan)
	errAggWg.Wait()

	if len(aggregatedErrs) > 0 {
		return errors.Join(aggregatedErrs...)
	}

	return nil
}

// captureUserInfo calls `/myself` API and store the current user information in secretInfo
func captureUserInfo(client *http.Client, token, domain, email string, secretInfo *SecretInfo) error {
	endPoint := fmt.Sprintf("%s/api/3/%s", fmt.Sprintf(baseURL, domain), endpoints[mySelf])
	respBody, statusCode, err := makeJiraRequest(client, endPoint, email, token)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var user JiraUser

		if err := json.Unmarshal(respBody, &user); err != nil {
			return err
		}

		secretInfo.UserInfo = user
		return nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Errorf("invalid email or api token")
	case http.StatusNotFound:
		return fmt.Errorf("domain not found: %s", domain)
	default:
		return fmt.Errorf("unexpected status code: %d for API: %s", statusCode, endpoints[mySelf])
	}
}

func captureProjects(client *http.Client, domain, email, token string, secretInfo *SecretInfo) (*ProjectSearchResponse, error) {
	endpoint := fmt.Sprintf("%s/api/3/%s", fmt.Sprintf(baseURL, domain), endpoints[getAllProjects])
	body, statusCode, err := makeJiraRequest(client, endpoint, email, token)
	if err != nil {
		return nil, err
	}

	if err := handleStatusCode(statusCode, endpoint); err != nil {
		return nil, err
	}

	var resp ProjectSearchResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal project response: %w", err)
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

		secretInfo.appendResource(resource, ResourceTypeProject)
	}

	return &resp, nil
}

func captureIssues(client *http.Client, domain, email, token, projectKey string, secretInfo *SecretInfo) error {
	path := fmt.Sprintf("api/3/%s", endpoints[searchIssues])
	query := fmt.Sprintf("jql=project=%s&fields=issuetype,summary,status", projectKey)
	endpoint := fmt.Sprintf("%s/%s?%s", fmt.Sprintf(baseURL, domain), path, query)

	body, statusCode, err := makeJiraRequest(client, endpoint, email, token)
	if err != nil {
		return err
	}

	if err := handleStatusCode(statusCode, endpoint); err != nil {
		return err
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

		secretInfo.appendResource(issueResource, ResourceTypeIssue)
	}

	return nil
}

func captureBoards(client *http.Client, domain, email, token string, secretInfo *SecretInfo) error {
	endpoint := fmt.Sprintf("%s/agile/1.0/%s", fmt.Sprintf(baseURL, domain), endpoints[getAllBoards])

	body, statusCode, err := makeJiraRequest(client, endpoint, email, token)
	if err != nil {
		return err
	}

	if err := handleStatusCode(statusCode, endpoint); err != nil {
		return err
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
		secretInfo.appendResource(boardResource, ResourceTypeBoard)
	}

	return nil
}

func captureUsers(client *http.Client, domain, email, token string, secretInfo *SecretInfo) error {
	endpoint := fmt.Sprintf("%s/api/3/%s", fmt.Sprintf(baseURL, domain), endpoints[getAllUsers])

	body, statusCode, err := makeJiraRequest(client, endpoint, email, token)
	if err != nil {
		return err
	}

	if err := handleStatusCode(statusCode, endpoint); err != nil {
		return err
	}

	var users []JiraUser
	if err := json.Unmarshal(body, &users); err != nil {
		return fmt.Errorf("failed to unmarshal user response: %w", err)
	}

	for _, user := range users {
		userResource := JiraResource{
			ID:   user.AccountID,
			Name: user.DisplayName,
			Type: ResourceTypeUser,
			Metadata: map[string]string{
				"Email":       user.EmailAddress,
				"AccountType": user.AccountType,
				"Active":      strconv.FormatBool(user.Active),
				"SelfURL":     user.Self,
			},
		}
		if user.AccountType != "app" {
			secretInfo.appendResource(userResource, ResourceTypeUser)
		}

	}

	return nil
}

func captureGroups(client *http.Client, domain, email, token string, secretInfo *SecretInfo) error {
	endpoint := fmt.Sprintf("%s/api/3/%s", fmt.Sprintf(baseURL, domain), endpoints[findGroups])

	body, statusCode, err := makeJiraRequest(client, endpoint, email, token)
	if err != nil {
		return err
	}

	if err := handleStatusCode(statusCode, endpoint); err != nil {
		return err
	}

	var groupResp JiraGroup
	if err := json.Unmarshal(body, &groupResp); err != nil {
		return fmt.Errorf("failed to unmarshal group response: %w", err)
	}

	for _, group := range groupResp.Groups {
		metadata := map[string]string{
			"HTML": group.HTML,
		}
		if len(group.Labels) > 0 {
			for i, label := range group.Labels {
				metadata[fmt.Sprintf("Label%d_Text", i)] = label.Text
				metadata[fmt.Sprintf("Label%d_Title", i)] = label.Title
				metadata[fmt.Sprintf("Label%d_Type", i)] = label.Type
			}
		}

		groupResource := JiraResource{
			ID:       group.GroupID,
			Name:     group.Name,
			Type:     ResourceTypeGroup,
			Metadata: metadata,
		}

		secretInfo.appendResource(groupResource, ResourceTypeGroup)
	}

	return nil
}

func captureAuditLogs(client *http.Client, domain, email, token string, secretInfo *SecretInfo) error {
	endpoint := fmt.Sprintf("%s/api/3/%s", fmt.Sprintf(baseURL, domain), endpoints[getAuditRecords])

	body, statusCode, err := makeJiraRequest(client, endpoint, email, token)
	if err != nil {
		return err
	}

	if err := handleStatusCode(statusCode, endpoint); err != nil {
		return err
	}

	var auditResp AuditRecord
	if err := json.Unmarshal(body, &auditResp); err != nil {
		return fmt.Errorf("failed to unmarshal audit logs: %w", err)
	}

	for _, record := range auditResp.Records {
		metadata := map[string]string{
			"Summary":  record.Summary,
			"Created":  record.Created,
			"Category": record.Category,
			"Type":     record.ObjectItem.TypeName,
			"Object":   record.ObjectItem.Name,
		}

		if record.AuthorAccount != "" {
			metadata["AuthorAccountID"] = record.AuthorAccount
		}
		if record.RemoteAddress != "" {
			metadata["RemoteAddress"] = record.RemoteAddress
		}

		for i, item := range record.AssociatedItems {
			metadata[fmt.Sprintf("AssociatedItem%d_Name", i)] = item.Name
			metadata[fmt.Sprintf("AssociatedItem%d_Type", i)] = item.TypeName
		}

		for i, change := range record.ChangedValues {
			metadata[fmt.Sprintf("ChangedField%d_Name", i)] = change.FieldName
			metadata[fmt.Sprintf("ChangedField%d_To", i)] = change.ChangedTo
		}

		resource := JiraResource{
			ID:       fmt.Sprintf("%d", record.ID),
			Name:     record.Summary,
			Type:     ResourceTypeAuditRecord,
			Metadata: metadata,
		}

		secretInfo.appendResource(resource, ResourceTypeAuditRecord)
	}

	return nil
}

func handleStatusCode(statusCode int, endpoint string) error {
	switch {
	case statusCode == http.StatusOK:
		return nil
	case statusCode == http.StatusBadRequest:
		return fmt.Errorf("bad request for API: %s", endpoint)
	case statusCode == http.StatusUnauthorized, statusCode == http.StatusForbidden,
		statusCode == http.StatusNotFound, statusCode == http.StatusConflict:
		return nil
	default:
		return fmt.Errorf("unexpected status code: %d for API: %s", statusCode, endpoint)
	}
}
