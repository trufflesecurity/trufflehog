package launchdarkly

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
)

var (
	baseURL = "https://app.launchdarkly.com/api"

	endpoints = map[string]string{
		"callerIdentity": "/v2/caller-identity",
		"getToken":       "/v2/tokens/%s", // require token id
		"getRole":        "/v2/roles/%s",  // require role id
		applicationType:  "/v2/applications",
		repositoryType:   "/v2/code-refs/repositories",
		projectType:      "/v2/projects",
		environmentType:  "/v2/projects/%s/environments",                // require project key
		experimentType:   "/v2/projects/%s/environments/%s/experiments", // require project key and env key
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

// makeLaunchDarklyRequest send the HTTP GET API request to passed url with passed token and return response body and status code
func makeLaunchDarklyRequest(client *http.Client, endpoint, token string) ([]byte, int, error) {
	// create request
	req, err := http.NewRequest(http.MethodGet, baseURL+endpoint, http.NoBody)
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
		errChan        = make(chan error, 5)
		aggregatedErrs = make([]string, 0)
	)

	wg.Add(1)
	go func() {
		defer wg.Done()

		if err := captureApplications(client, token, secretInfo); err != nil {
			errChan <- err
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()

		if err := captureRepositories(client, token, secretInfo); err != nil {
			errChan <- err
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()

		if err := captureProjects(client, token, secretInfo); err != nil {
			errChan <- err
		}

		// for each project capture it's environments
		for _, project := range secretInfo.listResourceByType(projectType) {
			if err := captureProjectEnv(client, token, project, secretInfo); err != nil {
				errChan <- err
			}

			// for each environment capture it's experiments
			for _, env := range secretInfo.listResourceByType(environmentType) {
				fmt.Println("here afer getting list resource by env type")
				if err := captureProjectEnvExperiments(client, token, project.MetaData[MetadataKey], env, secretInfo); err != nil {
					errChan <- err
				}
			}
		}

	}()

	wg.Wait()
	close(errChan)

	// collect all errors
	for err := range errChan {
		aggregatedErrs = append(aggregatedErrs, err.Error())
	}

	if len(aggregatedErrs) > 0 {
		return errors.New(strings.Join(aggregatedErrs, ", "))
	}

	return nil
}

// docs: https://launchdarkly.com/docs/api/applications-beta/get-applications
func captureApplications(client *http.Client, token string, secretInfo *SecretInfo) error {
	response, statusCode, err := makeLaunchDarklyRequest(client, endpoints[applicationType], token)
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
				Type: applicationType,
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
	response, statusCode, err := makeLaunchDarklyRequest(client, endpoints[repositoryType], token)
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
				Type: repositoryType,
				MetaData: map[string]string{
					"Default branch": repository.DefaultBranch,
					"Version":        fmt.Sprintf("%d", repository.Version),
					"Source link":    repository.SourceLink,
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
	response, statusCode, err := makeLaunchDarklyRequest(client, endpoints[projectType], token)
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
				Type: projectType,
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

// docs: https://launchdarkly.com/docs/api/environments/get-environments-by-project
func captureProjectEnv(client *http.Client, token string, parent Resource, secretInfo *SecretInfo) error {
	projectKey, exist := parent.MetaData[MetadataKey]
	if !exist {
		return errors.New("project key not found")
	}

	response, statusCode, err := makeLaunchDarklyRequest(client, fmt.Sprintf(endpoints[environmentType], projectKey), token)
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
			secretInfo.appendResource(Resource{
				ID:   fmt.Sprintf("launchdarkly/%s/env/%s", projectKey, env.ID),
				Name: env.Name,
				Type: environmentType,
				MetaData: map[string]string{
					MetadataKey: env.Key,
				},
				ParentResource: &parent,
			})
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
		return errors.New("project key not found")
	}

	response, statusCode, err := makeLaunchDarklyRequest(client, fmt.Sprintf(endpoints[experimentType], projectKey, envKey), token)
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
			secretInfo.appendResource(Resource{
				ID:   fmt.Sprintf("launchdarkly/%s/env/%s/exp/%s", projectKey, envKey, exp.ID),
				Name: exp.Name,
				Type: experimentType,
				MetaData: map[string]string{
					MetadataKey:     exp.Key,
					"Maintainer ID": exp.MaintainerID,
				},
				ParentResource: &parent,
			})
		}

		return nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil
	default:
		return fmt.Errorf("unexpected status code: %d", statusCode)
	}
}
