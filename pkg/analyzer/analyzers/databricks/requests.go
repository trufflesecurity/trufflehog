package databricks

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

var (
	apiEndpoints = map[ResourceType]string{
		CurrentUser:      "/api/2.0/preview/scim/v2/Me",
		TokensInfo:       "/api/2.0/token-management/tokens",
		TokenPermissions: "/api/2.0/permissions/authorization/tokens/permissionLevels",
		Repositories:     "/api/2.0/repos",
		GitCredentials:   "/api/2.0/git-credentials",
		Jobs:             "/api/2.2/jobs/list",
		Clusters:         "/api/2.1/clusters/list",
		Groups:           "/api/2.0/preview/scim/v2/Groups",
		Users:            "/api/2.0/preview/scim/v2/Users",
		/*
			TODO:
				- https://docs.databricks.com/api/gcp/workspace/workspace/list (list content inside path)
				- http://docs.databricks.com/api/gcp/workspace/libraries/allclusterlibrarystatuses (list cluster statuses)
		*/
	}
)

// makeDataBricksRequest send the API request to passed url with passed key as access token and return response body and status code
func makeDataBricksRequest(client *http.Client, endpoint, token string) ([]byte, int, error) {
	// create request
	req, err := http.NewRequest(http.MethodGet, "https://"+endpoint, http.NoBody)
	if err != nil {
		return nil, 0, err
	}

	// add key in the header
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))

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

func captureDataBricksResources(client *http.Client, domain, token string, secretInfo *SecretInfo) error {
	if err := captureRepos(client, domain, token, secretInfo); err != nil {
		return err
	}

	if err := captureGitCreds(client, domain, token, secretInfo); err != nil {
		return err
	}

	if err := captureJobs(client, domain, token, secretInfo); err != nil {
		return err
	}

	if err := captureClusters(client, domain, token, secretInfo); err != nil {
		return err
	}

	if err := captureGroups(client, domain, token, secretInfo); err != nil {
		return err
	}

	if err := captureUsers(client, domain, token, secretInfo); err != nil {
		return err
	}

	return nil
}

func captureUserInfo(client *http.Client, domain, token string, secretInfo *SecretInfo) error {
	respBody, statusCode, err := makeDataBricksRequest(client, domain+apiEndpoints[CurrentUser], token)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var user CurrentUserInfo

		if err := json.Unmarshal(respBody, &user); err != nil {
			return err
		}

		secretInfo.UserInfo = User{
			ID:       user.ID,
			UserName: user.UserName,
		}

		for _, email := range user.Emails {
			if email.Primary {
				secretInfo.UserInfo.PrimaryEmail = email.Value
			}
		}

		return nil
	case http.StatusUnauthorized:
		return fmt.Errorf("invalid/expired personal access token")
	default:
		return fmt.Errorf("unexpected status code: %d for API: %s", statusCode, apiEndpoints[CurrentUser])
	}
}

func captureTokensInfo(client *http.Client, domain, token string, secretInfo *SecretInfo) error {
	respBody, statusCode, err := makeDataBricksRequest(client, domain+apiEndpoints[TokensInfo], token)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var tokens Tokens

		if err := json.Unmarshal(respBody, &tokens); err != nil {
			return err
		}

		for _, token := range tokens.TokensInfo {
			t := Token{
				ID:          token.ID,
				Name:        token.Name,
				ExpiryTime:  readableTime(token.ExpiryTime),
				LastUsedDay: readableTime(token.LastUsedDay),
				CreatedBy:   token.CreatedBy,
			}

			secretInfo.Tokens = append(secretInfo.Tokens, t)
		}

		return nil
	case http.StatusUnauthorized:
		return fmt.Errorf("invalid/expired personal access token")
	default:
		return fmt.Errorf("unexpected status code: %d for API: %s", statusCode, apiEndpoints[CurrentUser])
	}
}

func captureTokenPermissions(client *http.Client, domain, token string, secretInfo *SecretInfo) error {
	respBody, statusCode, err := makeDataBricksRequest(client, domain+apiEndpoints[TokenPermissions], token)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var permissions Permissions

		if err := json.Unmarshal(respBody, &permissions); err != nil {
			return err
		}

		for _, item := range permissions.PermissionLevels {
			secretInfo.TokenPermissionLevels = append(secretInfo.TokenPermissionLevels, item.PermissionLevel)
		}

		return nil
	case http.StatusUnauthorized:
		return fmt.Errorf("invalid/expired personal access token")
	default:
		return fmt.Errorf("unexpected status code: %d for API: %s", statusCode, apiEndpoints[CurrentUser])
	}
}

func captureRepos(client *http.Client, domain, token string, secretInfo *SecretInfo) error {
	respBody, statusCode, err := makeDataBricksRequest(client, domain+apiEndpoints[Repositories], token)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var repos ReposResponse

		if err := json.Unmarshal(respBody, &repos); err != nil {
			return err
		}

		for _, repo := range repos.Repositories {
			if repo.ID == "" {
				repo.ID = repo.URL
			}

			secretInfo.Resources = append(secretInfo.Resources, DataBricksResource{
				ID:   repo.ID,
				Name: repo.Path,
				Type: Repositories.String(),
				Metadata: map[string]string{
					"provider": repo.Provider,
					"url":      repo.URL,
				},
			})
		}

		return nil
	case http.StatusUnauthorized:
		return fmt.Errorf("invalid/expired personal access token")
	default:
		return fmt.Errorf("unexpected status code: %d for API: %s", statusCode, apiEndpoints[CurrentUser])
	}
}

func captureGitCreds(client *http.Client, domain, token string, secretInfo *SecretInfo) error {
	respBody, statusCode, err := makeDataBricksRequest(client, domain+apiEndpoints[GitCredentials], token)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var creds GitCreds

		if err := json.Unmarshal(respBody, &creds); err != nil {
			return err
		}

		for _, credential := range creds.Credentials {
			secretInfo.Resources = append(secretInfo.Resources, DataBricksResource{
				ID:   credential.ID,
				Name: credential.UserName,
				Type: GitCredentials.String(),
				Metadata: map[string]string{
					"provider": credential.Provider,
				},
			})
		}

		return nil
	case http.StatusUnauthorized:
		return fmt.Errorf("invalid/expired personal access token")
	default:
		return fmt.Errorf("unexpected status code: %d for API: %s", statusCode, apiEndpoints[CurrentUser])
	}
}

func captureJobs(client *http.Client, domain, token string, secretInfo *SecretInfo) error {
	respBody, statusCode, err := makeDataBricksRequest(client, domain+apiEndpoints[Jobs], token)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var jobs JobsResponse

		if err := json.Unmarshal(respBody, &jobs); err != nil {
			return err
		}

		for _, job := range jobs.Jobs {
			secretInfo.Resources = append(secretInfo.Resources, DataBricksResource{
				ID:   job.ID,
				Name: job.Name,
				Type: Jobs.String(),
				Metadata: map[string]string{
					"description": job.Description,
				},
			})
		}

		return nil
	case http.StatusUnauthorized:
		return fmt.Errorf("invalid/expired personal access token")
	default:
		return fmt.Errorf("unexpected status code: %d for API: %s", statusCode, apiEndpoints[CurrentUser])
	}
}

func captureClusters(client *http.Client, domain, token string, secretInfo *SecretInfo) error {
	respBody, statusCode, err := makeDataBricksRequest(client, domain+apiEndpoints[Clusters], token)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var clusters ClustersResponse

		if err := json.Unmarshal(respBody, &clusters); err != nil {
			return err
		}

		for _, cluster := range clusters.Clusters {
			secretInfo.Resources = append(secretInfo.Resources, DataBricksResource{
				ID:   cluster.ID,
				Name: cluster.Name,
				Type: Clusters.String(),
				Metadata: map[string]string{
					"created by": cluster.CreatedBy,
				},
			})
		}

		return nil
	case http.StatusUnauthorized:
		return fmt.Errorf("invalid/expired personal access token")
	default:
		return fmt.Errorf("unexpected status code: %d for API: %s", statusCode, apiEndpoints[CurrentUser])
	}
}

func captureGroups(client *http.Client, domain, token string, secretInfo *SecretInfo) error {
	respBody, statusCode, err := makeDataBricksRequest(client, domain+apiEndpoints[Groups], token)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var groups GroupsResponse

		if err := json.Unmarshal(respBody, &groups); err != nil {
			return err
		}

		for _, group := range groups.Resources {
			secretInfo.Resources = append(secretInfo.Resources, DataBricksResource{
				ID:   group.ID,
				Name: group.Name,
				Type: Groups.String(),
			})
		}

		return nil
	case http.StatusUnauthorized:
		return fmt.Errorf("invalid/expired personal access token")
	default:
		return fmt.Errorf("unexpected status code: %d for API: %s", statusCode, apiEndpoints[CurrentUser])
	}
}

func captureUsers(client *http.Client, domain, token string, secretInfo *SecretInfo) error {
	respBody, statusCode, err := makeDataBricksRequest(client, domain+apiEndpoints[Users], token)
	if err != nil {
		return err
	}

	switch statusCode {
	case http.StatusOK:
		var users UsersResponse

		if err := json.Unmarshal(respBody, &users); err != nil {
			return err
		}

		for _, user := range users.Resources {
			secretInfo.Resources = append(secretInfo.Resources, DataBricksResource{
				ID:   user.ID,
				Name: user.UserName,
				Type: Users.String(),
				Metadata: map[string]string{
					"active": fmt.Sprintf("%t", user.Active),
				},
			})
		}

		return nil
	case http.StatusUnauthorized:
		return fmt.Errorf("invalid/expired personal access token")
	default:
		return fmt.Errorf("unexpected status code: %d for API: %s", statusCode, apiEndpoints[CurrentUser])
	}
}

func readableTime(timestamp int) string {
	timestampMillis := int64(timestamp)
	t := time.Unix(timestampMillis/1000, (timestampMillis%1000)*int64(time.Millisecond))

	return t.Format("2006-01-02 15:04:05")
}
