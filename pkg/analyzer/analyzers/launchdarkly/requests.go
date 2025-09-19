package launchdarkly

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"
)

const defaultTimeout = 5 * time.Second

var (
	baseURL = "https://app.launchdarkly.com/api"

	endpoints = map[string]string{
		// user information APIs
		"callerIdentity": "/v2/caller-identity",
		"getToken":       "/v2/tokens/%s", // require token id
		"getRole":        "/v2/roles/%s",  // require role id
		// resource APIs
		applicationKey:  "/v2/applications",
		repositoryKey:   "/v2/code-refs/repositories",
		projectKey:      "/v2/projects",
		environmentKey:  "/v2/projects/%s/environments",                // require project key
		featureFlagsKey: "/v2/flags/%s",                                // require project key
		experimentKey:   "/v2/projects/%s/environments/%s/experiments", // require project key and env key
		holdoutsKey:     "/v2/projects/%s/environments/%s/holdouts",    // require project key and env key
		membersKey:      "/v2/members",
		destinationsKey: "/v2/destinations",
		templatesKey:    "/v2/templates",
		teamsKey:        "/v2/teams",
		webhooksKey:     "/v2/webhooks",
		/*
			TODO:
			release pipelines: https://launchdarkly.com/docs/api/release-pipelines-beta/get-all-release-pipelines (Beta)
			insight deployments: https://launchdarkly.com/docs/api/insights-deployments-beta/get-deployments (Beta)
			delivery configuration: https://launchdarkly.com/docs/api/integration-delivery-configurations-beta/get-integration-delivery-configuration-by-environment (Beta)
			metrics: https://launchdarkly.com/docs/api/metrics-beta/get-metric-groups (Beta)
		*/
	}
)

// applicationsResponse is the response of /v2/applications API
type applicationsResponse struct {
	Items []struct {
		Key        string `json:"key"`
		Name       string `json:"name"`
		Kind       string `json:"kind"`
		Maintainer struct {
			Email string `json:"email"`
		} `json:"_maintainer"`
	} `json:"items"`
}

// repositoriesResponse is the response of /v2/code-refs/repositories API
type repositoriesResponse struct {
	Items []struct {
		Name          string `json:"name"`
		Type          string `json:"type"`
		DefaultBranch string `json:"defaultBranch"`
		SourceLink    string `json:"sourceLink"`
		Version       int    `json:"version"`
	} `json:"items"`
}

// projectsResponse is the response of /v2/projects API
type projectsResponse struct {
	Items []struct {
		ID   string `json:"_id"`
		Key  string `json:"key"`
		Name string `json:"name"`
	} `json:"items"`
}

// featureFlagsResponse is the response of /v2/flags/<project_id> API
type featureFlagsResponse struct {
	Items []struct {
		Key  string `json:"key"`
		Name string `json:"name"`
		Kind string `json:"kind"`
	} `json:"items"`
}

// environmentsResponse is the response of /v2/projects/<proj_key>/environments API
type environmentsResponse struct {
	Items []struct {
		ID   string `json:"_id"`
		Key  string `json:"key"`
		Name string `json:"name"`
	} `json:"items"`
}

// experimentResponse is the response of /v2/projects/<proj_id>/env/<env_id>/experiments
type experimentResponse struct {
	Items []struct {
		ID           string `json:"_id"`
		Key          string `json:"key"`
		Name         string `json:"name"`
		MaintainerID string `json:"_maintainerId"`
	} `json:"items"`
}

// membersResponse is the response of /v2/members API
type membersResponse struct {
	Items []struct {
		ID        string `json:"_id"`
		Role      string `json:"role"`
		Email     string `json:"email"`
		FirstName string `json:"firstName"`
		LastName  string `json:"lastName"`
	} `json:"items"`
}

// holdoutsResponse is the response of /v2/projects/<project_id>/environments/<env_id>/holdouts API
type holdoutsResponse struct {
	Items []struct {
		ID     string `json:"_id"`
		Name   string `json:"name"`
		Key    string `json:"key"`
		Status string `json:"status"`
	} `json:"items"`
}

// destinationsResponse is the response of /v2/destinations API
type destinationsResponse struct {
	Items []struct {
		ID      string `json:"_id"`
		Name    string `json:"name"`
		Kind    string `json:"kind"`
		Version int    `json:"version"`
	} `json:"items"`
}

// templatesResponse is the response of /v2/templates API
type templatesResponse struct {
	Items []struct {
		ID   string `json:"_id"`
		Key  string `json:"_key"`
		Name string `json:"name"`
	} `json:"items"`
}

// teamsResponse is the response of /v2/teams API
type teamsResponse struct {
	Items []struct {
		Key   string `json:"key"`
		Name  string `json:"name"`
		Roles struct {
			TotalCount int `json:"totalCount"`
		} `json:"roles"`
		Members struct {
			TotalCount int `json:"totalCount"`
		} `json:"members"`
		Projects struct {
			TotalCount int `json:"totalCount"`
		} `json:"projects"`
	} `json:"items"`
}

// webhooksResponse is the response of /v2/webhooks API
type webhooksResponse struct {
	Items []struct {
		ID   string `json:"_id"`
		Name string `json:"name"`
		Url  string `json:"url"`
	} `json:"items"`
}

// makeLaunchDarklyRequest send the HTTP GET API request to passed url with passed token and return response body and status code
func makeLaunchDarklyRequest(client *http.Client, endpoint, token string) ([]byte, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	// create request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+endpoint, http.NoBody)
	if err != nil {
		return nil, 0, err
	}

	// add required keys in the header
	req.Header.Set("Authorization", token)
	req.Header.Set("Content-Type", "application/json")

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

func CaptureResources(client *http.Client, token string, secretInfo *SecretInfo) error {
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

	// capture top-level resources
	launchTask(func() error { return captureApplications(client, token, secretInfo) })
	launchTask(func() error { return captureRepositories(client, token, secretInfo) })

	// capture projects
	launchTask(func() error {
		if err := captureProjects(client, token, secretInfo); err != nil {
			return err
		}

		// capture project sub resources
		projects := secretInfo.listResourceByType(projectKey)
		for _, proj := range projects {
			launchTask(func() error { return captureProjectFeatureFlags(client, token, proj, secretInfo) })
			launchTask(func() error { return captureProjectEnv(client, token, proj, secretInfo) })
		}

		return nil
	})

	launchTask(func() error { return captureMembers(client, token, secretInfo) })
	launchTask(func() error { return captureDestinations(client, token, secretInfo) })
	launchTask(func() error { return captureTemplates(client, token, secretInfo) })
	launchTask(func() error { return captureTeams(client, token, secretInfo) })
	launchTask(func() error { return captureWebhooks(client, token, secretInfo) })

	wg.Wait()
	close(errChan)
	errAggWg.Wait()

	if len(aggregatedErrs) > 0 {
		return errors.Join(aggregatedErrs...)
	}

	return nil
}

// docs: https://launchdarkly.com/docs/api/applications-beta/get-applications
func captureApplications(client *http.Client, token string, secretInfo *SecretInfo) error {
	response, statusCode, err := makeLaunchDarklyRequest(client, endpoints[applicationKey], token)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var applications = applicationsResponse{}

		if err := json.Unmarshal(response, &applications); err != nil {
			return err
		}

		for _, application := range applications.Items {
			resource := Resource{
				ID:   fmt.Sprintf("launchdarkly/app/%s", application.Key),
				Name: application.Name,
				Type: applicationKey,
				MetaData: map[string]string{
					"Maintainer Email": application.Maintainer.Email,
					"Kind":             application.Kind,
					MetadataKey:        application.Key,
				},
			}

			secretInfo.appendResource(resource)
		}

		return nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil
	default:
		return fmt.Errorf("unexpected status code: %d", statusCode)
	}
}

// docs: https://launchdarkly.com/docs/api/code-references/get-repositories
func captureRepositories(client *http.Client, token string, secretInfo *SecretInfo) error {
	response, statusCode, err := makeLaunchDarklyRequest(client, endpoints[repositoryKey], token)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var repositories = repositoriesResponse{}

		if err := json.Unmarshal(response, &repositories); err != nil {
			return err
		}

		for _, repository := range repositories.Items {
			resource := Resource{
				ID:   fmt.Sprintf("%s/repo/%s/%d", repository.Type, repository.Name, repository.Version), // no unique id exist, so we make one
				Name: repository.Name,
				Type: repositoryKey,
				MetaData: map[string]string{
					"Default branch": repository.DefaultBranch,
					"Version":        strconv.Itoa(repository.Version),
					"Source link":    repository.SourceLink,
					MetadataKey:      repositoryKey,
				},
			}

			secretInfo.appendResource(resource)
		}

		return nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil
	default:
		return fmt.Errorf("unexpected status code: %d", statusCode)
	}
}

// docs: https://launchdarkly.com/docs/api/projects/get-projects
func captureProjects(client *http.Client, token string, secretInfo *SecretInfo) error {
	response, statusCode, err := makeLaunchDarklyRequest(client, endpoints[projectKey], token)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var projects = projectsResponse{}

		if err := json.Unmarshal(response, &projects); err != nil {
			return err
		}

		for _, project := range projects.Items {
			secretInfo.appendResource(Resource{
				ID:   fmt.Sprintf("launchdarkly/proj/%s", project.ID),
				Name: project.Name,
				Type: projectKey,
				MetaData: map[string]string{
					MetadataKey: project.Key,
				},
			})
		}

		return nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil
	default:
		return fmt.Errorf("unexpected status code: %d", statusCode)
	}
}

// docs: https://launchdarkly.com/docs/api/feature-flags/get-feature-flags
func captureProjectFeatureFlags(client *http.Client, token string, parent Resource, secretInfo *SecretInfo) error {
	projectKey, exist := parent.MetaData[MetadataKey]
	if !exist {
		return errors.New("project key not found")
	}

	response, statusCode, err := makeLaunchDarklyRequest(client, fmt.Sprintf(endpoints[featureFlagsKey], projectKey), token)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var flags = featureFlagsResponse{}

		if err := json.Unmarshal(response, &flags); err != nil {
			return err
		}

		for _, flag := range flags.Items {
			resource := Resource{
				ID:   fmt.Sprintf("launchdarkly/proj/%s/flag/%s", projectKey, flag.Key),
				Name: flag.Name,
				Type: featureFlagsKey,
				MetaData: map[string]string{
					"Kind": flag.Kind,
				},
				ParentResource: &parent,
			}

			secretInfo.appendResource(resource)
		}

		return nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil
	default:
		return fmt.Errorf("unexpected status code: %d", statusCode)
	}
}

// docs: https://launchdarkly.com/docs/api/environments/get-environments-by-project
func captureProjectEnv(client *http.Client, token string, parent Resource, secretInfo *SecretInfo) error {
	projectKey, exist := parent.MetaData[MetadataKey]
	if !exist {
		return errors.New("project key not found")
	}

	response, statusCode, err := makeLaunchDarklyRequest(client, fmt.Sprintf(endpoints[environmentKey], projectKey), token)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var envs = environmentsResponse{}

		if err := json.Unmarshal(response, &envs); err != nil {
			return err
		}

		for _, env := range envs.Items {
			resource := Resource{
				ID:   fmt.Sprintf("launchdarkly/%s/env/%s", projectKey, env.ID),
				Name: env.Name,
				Type: environmentKey,
				MetaData: map[string]string{
					MetadataKey: env.Key,
				},
				ParentResource: &parent,
			}

			secretInfo.appendResource(resource)

			// capture project env child resources
			if err := captureProjectEnvExperiments(client, token, projectKey, resource, secretInfo); err != nil {
				return err
			}

			if err := captureProjectHoldouts(client, token, projectKey, resource, secretInfo); err != nil {
				return err
			}
		}

		return nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil
	default:
		return fmt.Errorf("unexpected status code: %d", statusCode)
	}
}

// docs: https://launchdarkly.com/docs/api/experiments/get-experiments
func captureProjectEnvExperiments(client *http.Client, token string, projectKey string, parent Resource, secretInfo *SecretInfo) error {
	envKey, exist := parent.MetaData[MetadataKey]
	if !exist {
		return errors.New("env key not found")
	}

	response, statusCode, err := makeLaunchDarklyRequest(client, fmt.Sprintf(endpoints[experimentKey], projectKey, envKey), token)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var exps = experimentResponse{}

		if err := json.Unmarshal(response, &exps); err != nil {
			return err
		}

		for _, exp := range exps.Items {
			resource := Resource{
				ID:   fmt.Sprintf("launchdarkly/%s/env/%s/exp/%s", projectKey, envKey, exp.ID),
				Name: exp.Name,
				Type: experimentKey,
				MetaData: map[string]string{
					MetadataKey:    exp.Key,
					"Maintiner ID": exp.MaintainerID,
				},
				ParentResource: &parent,
			}

			secretInfo.appendResource(resource)
		}

		return nil
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
		return nil
	case http.StatusTooManyRequests:
		time.Sleep(1 * time.Second)
		return nil
	default:
		return fmt.Errorf("unexpected status code: %d", statusCode)
	}
}

// docs: https://launchdarkly.com/docs/api/holdouts-beta/get-all-holdouts
func captureProjectHoldouts(client *http.Client, token string, projectKey string, parent Resource, secretInfo *SecretInfo) error {
	envKey, exist := parent.MetaData[MetadataKey]
	if !exist {
		return errors.New("env key not found")
	}

	response, statusCode, err := makeLaunchDarklyRequest(client, fmt.Sprintf(endpoints[holdoutsKey], projectKey, envKey), token)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var holdouts = holdoutsResponse{}

		if err := json.Unmarshal(response, &holdouts); err != nil {
			return err
		}

		for _, holdout := range holdouts.Items {
			resource := Resource{
				ID:   fmt.Sprintf("launchdarkly/%s/env/%s/holdout/%s", projectKey, envKey, holdout.ID),
				Name: holdout.Name,
				Type: holdoutsKey,
				MetaData: map[string]string{
					"Status":    holdout.Status,
					holdoutsKey: holdout.Key,
				},
				ParentResource: &parent,
			}

			secretInfo.appendResource(resource)
		}

		return nil
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
		return nil
	default:
		return fmt.Errorf("unexpected status code: %d", statusCode)
	}
}

// docs: https://launchdarkly.com/docs/api/account-members/get-members
func captureMembers(client *http.Client, token string, secretInfo *SecretInfo) error {
	response, statusCode, err := makeLaunchDarklyRequest(client, endpoints[membersKey], token)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var members = membersResponse{}

		if err := json.Unmarshal(response, &members); err != nil {
			return err
		}

		for _, member := range members.Items {
			resource := Resource{
				ID:   fmt.Sprintf("launchdarkly/member/%s", member.ID),
				Name: member.FirstName + " " + member.LastName,
				Type: membersKey,
				MetaData: map[string]string{
					"Role":  member.Role,
					"Email": member.Email,
				},
			}

			secretInfo.appendResource(resource)
		}

		return nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil
	default:
		return fmt.Errorf("unexpected status code: %d", statusCode)
	}
}

// docs: https://launchdarkly.com/docs/api/data-export-destinations/get-destinations
func captureDestinations(client *http.Client, token string, secretInfo *SecretInfo) error {
	response, statusCode, err := makeLaunchDarklyRequest(client, endpoints[destinationsKey], token)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var destinations = destinationsResponse{}

		if err := json.Unmarshal(response, &destinations); err != nil {
			return err
		}

		for _, destination := range destinations.Items {
			resource := Resource{
				ID:   fmt.Sprintf("launchdarkly/destination/%s", destination.ID),
				Name: destination.Name,
				Type: destinationsKey,
				MetaData: map[string]string{
					"Kind":    destination.Kind,
					"Version": strconv.Itoa(destination.Version),
				},
			}

			secretInfo.appendResource(resource)
		}

		return nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil
	default:
		return fmt.Errorf("unexpected status code: %d", statusCode)
	}
}

// docs: https://launchdarkly.com/docs/api/workflow-templates/get-workflow-templates
func captureTemplates(client *http.Client, token string, secretInfo *SecretInfo) error {
	response, statusCode, err := makeLaunchDarklyRequest(client, endpoints[templatesKey], token)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var templates = templatesResponse{}

		if err := json.Unmarshal(response, &templates); err != nil {
			return err
		}

		for _, template := range templates.Items {
			resource := Resource{
				ID:   fmt.Sprintf("launchdarkly/templates/%s", template.ID),
				Name: template.Name,
				Type: templatesKey,
			}

			secretInfo.appendResource(resource)
		}

		return nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil
	default:
		return fmt.Errorf("unexpected status code: %d", statusCode)
	}
}

// docs: https://launchdarkly.com/docs/api/teams/get-teams
func captureTeams(client *http.Client, token string, secretInfo *SecretInfo) error {
	response, statusCode, err := makeLaunchDarklyRequest(client, endpoints[teamsKey], token)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var teams = teamsResponse{}

		if err := json.Unmarshal(response, &teams); err != nil {
			return err
		}

		for _, team := range teams.Items {
			resource := Resource{
				ID:   fmt.Sprintf("launchdarkly/teams/%s", team.Key),
				Name: team.Name,
				Type: teamsKey,
				MetaData: map[string]string{
					"Total Roles Count":    strconv.Itoa(team.Roles.TotalCount),
					"Total Memvers Count":  strconv.Itoa(team.Members.TotalCount),
					"Total Projects Count": strconv.Itoa(team.Projects.TotalCount),
				},
			}

			secretInfo.appendResource(resource)
		}

		return nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil
	default:
		return fmt.Errorf("unexpected status code: %d", statusCode)
	}
}

// docs: https://launchdarkly.com/docs/api/webhooks/get-all-webhooks
func captureWebhooks(client *http.Client, token string, secretInfo *SecretInfo) error {
	response, statusCode, err := makeLaunchDarklyRequest(client, endpoints[webhooksKey], token)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var webhooks = webhooksResponse{}

		if err := json.Unmarshal(response, &webhooks); err != nil {
			return err
		}

		for _, webhook := range webhooks.Items {
			resource := Resource{
				ID:   fmt.Sprintf("launchdarkly/webhooks/%s", webhook.ID),
				Name: webhook.Name,
				Type: webhooksKey,
			}

			secretInfo.appendResource(resource)
		}

		return nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil
	default:
		return fmt.Errorf("unexpected status code: %d", statusCode)
	}
}
