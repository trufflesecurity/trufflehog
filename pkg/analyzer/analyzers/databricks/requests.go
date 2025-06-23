package databricks

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

var (
	// ErrUnauthorized is returned when the Databricks API answers with HTTP-401.
	errUnAuthorized = errors.New("invalid/expired personal access token")

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

// doAndDecode performs an authenticated GET request against the constructed
// Databricks URL and JSON-decodes the response into the supplied result.
//
// The generic type parameter T allows the caller to decide which concrete
// struct the response should be unmarshalled into:
func doAndDecode[T any](ctx context.Context, client *http.Client, domain string, rt ResourceType, token string, out *T) error {
	u := url.URL{
		Scheme: "https",
		Host:   domain,
		Path:   apiEndpoints[rt],
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), http.NoBody)
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Accept", "application/json")

	// Execute request and read / decode body. We stream directly into the
	// decoder instead of loading the whole response into memory first.
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("performing request: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK:
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return fmt.Errorf("decoding response: %w", err)
		}

		return nil
	case http.StatusUnauthorized:
		return errUnAuthorized
	default:
		return fmt.Errorf("unexpected status code %d for API %s", resp.StatusCode, apiEndpoints[rt])
	}
}

func captureDataBricksResources(ctx context.Context, client *http.Client, domain, token string, secretInfo *SecretInfo) error {
	if err := captureRepos(ctx, client, domain, token, secretInfo); err != nil {
		return err
	}

	if err := captureGitCreds(ctx, client, domain, token, secretInfo); err != nil {
		return err
	}

	if err := captureJobs(ctx, client, domain, token, secretInfo); err != nil {
		return err
	}

	if err := captureClusters(ctx, client, domain, token, secretInfo); err != nil {
		return err
	}

	if err := captureGroups(ctx, client, domain, token, secretInfo); err != nil {
		return err
	}

	if err := captureUsers(ctx, client, domain, token, secretInfo); err != nil {
		return err
	}

	return nil
}

func captureUserInfo(ctx context.Context, client *http.Client, domain, token string, secretInfo *SecretInfo) error {
	var user CurrentUserInfo

	if err := doAndDecode(ctx, client, domain, CurrentUser, token, &user); err != nil {
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
}

func captureTokensInfo(ctx context.Context, client *http.Client, domain, token string, secretInfo *SecretInfo) error {
	var tokens Tokens

	if err := doAndDecode(ctx, client, domain, TokensInfo, token, &tokens); err != nil {
		return err
	}

	for _, t := range tokens.TokensInfo {
		secretInfo.Tokens = append(secretInfo.Tokens, Token{
			ID:          t.ID,
			Name:        t.Name,
			ExpiryTime:  readableTime(t.ExpiryTime),
			LastUsedDay: readableTime(t.LastUsedDay),
			CreatedBy:   t.CreatedBy,
		})
	}

	return nil
}

func captureTokenPermissions(ctx context.Context, client *http.Client, domain, token string, secretInfo *SecretInfo) error {
	var permissions Permissions

	if err := doAndDecode(ctx, client, domain, TokenPermissions, token, &permissions); err != nil {
		return err
	}

	for _, item := range permissions.PermissionLevels {
		secretInfo.TokenPermissionLevels = append(secretInfo.TokenPermissionLevels, item.PermissionLevel)
	}

	return nil
}

func captureRepos(ctx context.Context, client *http.Client, domain, token string, secretInfo *SecretInfo) error {
	var repos ReposResponse

	if err := doAndDecode(ctx, client, domain, Repositories, token, &repos); err != nil {
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
}

func captureGitCreds(ctx context.Context, client *http.Client, domain, token string, secretInfo *SecretInfo) error {
	var creds GitCreds

	if err := doAndDecode(ctx, client, domain, GitCredentials, token, &creds); err != nil {
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
}

func captureJobs(ctx context.Context, client *http.Client, domain, token string, secretInfo *SecretInfo) error {
	var jobs JobsResponse

	if err := doAndDecode(ctx, client, domain, Jobs, token, &jobs); err != nil {
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
}

func captureClusters(ctx context.Context, client *http.Client, domain, token string, secretInfo *SecretInfo) error {
	var clusters ClustersResponse

	if err := doAndDecode(ctx, client, domain, Clusters, token, &clusters); err != nil {
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
}

func captureGroups(ctx context.Context, client *http.Client, domain, token string, secretInfo *SecretInfo) error {
	var groups GroupsResponse

	if err := doAndDecode(ctx, client, domain, Groups, token, &groups); err != nil {
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
}

func captureUsers(ctx context.Context, client *http.Client, domain, token string, secretInfo *SecretInfo) error {
	var users UsersResponse

	if err := doAndDecode(ctx, client, domain, Users, token, &users); err != nil {
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
}

func readableTime(timestamp int) string {
	timestampMillis := int64(timestamp)
	t := time.Unix(timestampMillis/1000, (timestampMillis%1000)*int64(time.Millisecond))

	return t.Format("2006-01-02 15:04:05")
}
