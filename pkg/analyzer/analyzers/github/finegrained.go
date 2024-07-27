package github

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"sort"
	"strings"

	"github.com/fatih/color"
	gh "github.com/google/go-github/v63/github"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
)

const (
	// Random values for testing
	RANDOM_STRING   = "FQ2pR.4voZg-gJfsqYKx_eLDNF_6BYhw8RL__"
	RANDOM_USERNAME = "d" + "ummy" + "acco" + "untgh" + "2024"
	RANDOM_REPO     = "te" + "st"
	RANDOM_INTEGER  = 4294967289

	// Permissions
	NO_ACCESS       = "No access"
	READ_ONLY       = "Read-only"
	READ_WRITE      = "Read and write"
	ERROR           = "Error"
	UNKNOWN         = "Unknown"
	NOT_IMPLEMENTED = "Not implemented"

	// Repo Permission Types
	ACTIONS              = "Actions"
	ADMINISTRATION       = "Administration"
	CODE_SCANNING_ALERTS = "Code scanning alerts"
	CODESPACES           = "Codespaces"
	CODESPACES_LIFECYCLE = "Codespaces lifecycle admin"
	CODESPACES_METADATA  = "Codespaces metadata"
	CODESPACES_SECRETS   = "Codespaces secrets"
	COMMIT_STATUSES      = "Commit statuses"
	CONTENTS             = "Contents"
	CUSTOM_PROPERTIES    = "Custom properties"
	DEPENDABOT_ALERTS    = "Dependabot alerts"
	DEPENDABOT_SECRETS   = "Dependabot secrets"
	DEPLOYMENTS          = "Deployments"
	ENVIRONMENTS         = "Environments" // Note: Addt'l permissions are not required (despite documentation).
	ISSUES               = "Issues"
	MERGE_QUEUES         = "Merge queues"
	METADATA             = "Metadata"
	PAGES                = "Pages"
	PULL_REQUESTS        = "Pull requests"
	REPO_SECURITY        = "Repository security advisories"
	SECRET_SCANNING      = "Secret scanning alerts"
	SECRETS              = "Secrets"
	VARIABLES            = "Variables"
	WEBHOOKS             = "Webhooks"
	WORKFLOWS            = "Workflows"

	// Account Permission Types
	BLOCK_USER             = "Block another user"
	CODESPACE_USER_SECRETS = "Codespace user secrets"
	EMAIL                  = "Email Addresses"
	FOLLOWERS              = "Followers"
	GPG_KEYS               = "GPG Keys"
	GISTS                  = "Gists"
	GIT_KEYS               = "Git SSH keys"
	LIMITS                 = "Interaction limits"
	PLAN                   = "Plan"
	PRIVATE_INVITES        = "Private invitations"
	PROFILE                = "Profile"
	SIGNING_KEYS           = "SSH signing keys"
	STARRING               = "Starring"
	WATCHING               = "Watching"
)

var repoPermFuncMap = map[string]func(client *gh.Client, repo *gh.Repository, acess string) (string, error){
	ACTIONS:              getActionsPermission,
	ADMINISTRATION:       getAdministrationPermission,
	CODE_SCANNING_ALERTS: getCodeScanningAlertsPermission,
	CODESPACES:           getCodespacesPermission,
	CODESPACES_LIFECYCLE: notImplemented, // ToDo: Implement. Docs make this look org-wide...not repo-based?
	CODESPACES_METADATA:  getCodespacesMetadataPermission,
	CODESPACES_SECRETS:   getCodespacesSecretsPermission,
	COMMIT_STATUSES:      getCommitStatusesPermission,
	CONTENTS:             getContentsPermission,
	CUSTOM_PROPERTIES:    notImplemented, // ToDo: Only supports orgs. Implement once have an org token.
	DEPENDABOT_ALERTS:    getDependabotAlertsPermission,
	DEPENDABOT_SECRETS:   getDependabotSecretsPermission,
	DEPLOYMENTS:          getDeploymentsPermission,
	ENVIRONMENTS:         getEnvironmentsPermission,
	ISSUES:               getIssuesPermission,
	MERGE_QUEUES:         notImplemented, // Skipped until API better documented
	METADATA:             getMetadataPermission,
	PAGES:                getPagesPermission,
	PULL_REQUESTS:        getPullRequestsPermission,
	REPO_SECURITY:        getRepoSecurityPermission,
	SECRET_SCANNING:      getSecretScanningPermission,
	SECRETS:              getSecretsPermission,
	VARIABLES:            getVariablesPermission,
	WEBHOOKS:             getWebhooksPermission,
	WORKFLOWS:            notImplemented, // ToDo: Skipped b/c would require us to create a release (High Risk function)
}

var acctPermFuncMap = map[string]func(client *gh.Client, user *gh.User) (string, error){
	BLOCK_USER:             getBlockUserPermission,
	CODESPACE_USER_SECRETS: getCodespacesUserPermission,
	EMAIL:                  getEmailPermission,
	FOLLOWERS:              getFollowersPermission,
	GPG_KEYS:               getGPGKeysPermission,
	GISTS:                  getGistsPermission,
	GIT_KEYS:               getGitKeysPermission,
	LIMITS:                 getLimitsPermission,
	PLAN:                   getPlanPermission,
	// PRIVATE_INVITES:        getPrivateInvitesPermission, // Skipped until API better documented
	PROFILE:      getProfilePermission,
	SIGNING_KEYS: getSigningKeysPermission,
	STARRING:     getStarringPermission,
	WATCHING:     getWatchingPermission,
}

// Define your custom formatter function
func permissionFormatter(key, val any) (string, string) {
	if strVal, ok := val.(string); ok {
		switch strVal {
		case NO_ACCESS:
			red := color.New(color.FgRed).SprintFunc()
			return red(key), red(NO_ACCESS)
		case READ_ONLY:
			yellow := color.New(color.FgYellow).SprintFunc()
			return yellow(key), yellow(READ_ONLY)
		case READ_WRITE:
			green := color.New(color.FgGreen).SprintFunc()
			return green(key), green(READ_WRITE)
		case UNKNOWN:
			blue := color.New(color.FgBlue).SprintFunc()
			return blue(key), blue(UNKNOWN)
		case NOT_IMPLEMENTED:
			blue := color.New(color.FgBlue).SprintFunc()
			return blue(key), blue(NOT_IMPLEMENTED)
		default:
			red := color.New(color.FgRed).SprintFunc()
			return red(key), red(ERROR)
		}
	}
	return fmt.Sprintf("%v", key), fmt.Sprintf("%v", val)
}

func notImplemented(client *gh.Client, repo *gh.Repository, currentAccess string) (string, error) {
	return NOT_IMPLEMENTED, nil
}

func getMetadataPermission(client *gh.Client, repo *gh.Repository, currentAccess string) (string, error) {
	// Risk: Extremely Low
	// -> GET request to /repos/{owner}/{repo}/collaborators
	_, resp, err := client.Repositories.ListCollaborators(context.Background(), *repo.Owner.Login, *repo.Name, nil)
	if err != nil {
		if resp.StatusCode == 403 {
			return NO_ACCESS, nil
		}
		return ERROR, err
	}
	// If no error, then we have read access
	return READ_ONLY, nil
}

func getActionsPermission(client *gh.Client, repo *gh.Repository, currentAccess string) (string, error) {
	if *repo.Private {
		// Risk: Extremely Low
		// -> GET request to /repos/{owner}/{repo}/actions/artifacts
		_, resp, err := client.Actions.ListArtifacts(context.Background(), *repo.Owner.Login, *repo.Name, nil)
		switch resp.StatusCode {
		case 403:
			return NO_ACCESS, nil
		case 200:
			break
		default:
			return ERROR, err
		}

		// Risk: Very, very low.
		// -> Unless the user has a workflow file named (see RANDOM_STRING above), this will always return 404 for users with READ_WRITE permissions.
		// -> POST request to /repos/{owner}/{repo}/actions/workflows/{workflow_id}/dispatches
		resp, err = client.Actions.CreateWorkflowDispatchEventByFileName(context.Background(), *repo.Owner.Login, *repo.Name, RANDOM_STRING, gh.CreateWorkflowDispatchEventRequest{})
		switch resp.StatusCode {
		case 403:
			return READ_ONLY, nil
		case 404:
			return READ_WRITE, nil
		case 200:
			log.Fatal("This shouldn't print. We are enabling a workflow based on a random string " + RANDOM_STRING + ", which most likely doesn't exist.")
			return READ_WRITE, nil
		default:
			return ERROR, err
		}
	} else {
		// Will only land here if already tested one public repo and got a 403.
		if currentAccess == UNKNOWN {
			return UNKNOWN, nil
		}
		// Risk: Very, very low.
		// -> Unless the user has a workflow file named (see RANDOM_STRING above), this will always return 404 for users with READ_WRITE permissions.
		// -> POST request to /repos/{owner}/{repo}/actions/workflows/{workflow_id}/dispatches
		resp, err := client.Actions.CreateWorkflowDispatchEventByFileName(context.Background(), *repo.Owner.Login, *repo.Name, RANDOM_STRING, gh.CreateWorkflowDispatchEventRequest{})
		switch resp.StatusCode {
		case 403:
			return UNKNOWN, nil
		case 404:
			return READ_WRITE, nil
		case 200:
			log.Fatal("This shouldn't print. We are enabling a workflow based on a random string " + RANDOM_STRING + ", which most likely doesn't exist.")
			return READ_WRITE, nil
		default:
			return ERROR, err
		}
	}
}

func getAdministrationPermission(client *gh.Client, repo *gh.Repository, currentAccess string) (string, error) {
	// Risk: Extremely Low
	// -> GET request to /repos/{owner}/{repo}/actions/permissions
	_, resp, err := client.Repositories.GetActionsPermissions(context.Background(), *repo.Owner.Login, *repo.Name)
	switch resp.StatusCode {
	case 403, 404:
		return NO_ACCESS, nil
	case 200:
		break
	default:
		return ERROR, err
	}

	// Risk: Extremely Low
	// -> GET request to /repos/{owner}/{repo}/rulesets/rule-suites
	req, err := client.NewRequest("GET", "https://api.github.com/repos/"+*repo.Owner.Login+"/"+*repo.Name+"/rulesets/rule-suites", nil)
	if err != nil {
		return ERROR, err
	}
	resp, err = client.Do(context.Background(), req, nil)
	switch resp.StatusCode {
	case 403:
		return READ_ONLY, nil
	case 200:
		return READ_WRITE, nil
	default:
		return ERROR, err
	}
}

func getCodeScanningAlertsPermission(client *gh.Client, repo *gh.Repository, currentAccess string) (string, error) {
	// Risk: Extremely Low
	// -> GET request to /repos/{owner}/{repo}/code-scanning/alerts
	_, resp, err := client.CodeScanning.ListAlertsForRepo(context.Background(), *repo.Owner.Login, *repo.Name, nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	body := string(bodyBytes)

	if strings.Contains(body, "Code scanning is not enabled for this repository") {
		return UNKNOWN, nil
	}

	switch {
	case resp.StatusCode == 403:
		return NO_ACCESS, nil
	case resp.StatusCode == 404:
		break
	case resp.StatusCode >= 200 && resp.StatusCode <= 299:
		break
	default:
		return ERROR, err
	}

	// Risk: Very Low
	// -> Even if user had an alert with the number (see RANDOM_INTEGER above), this should error 422 due to the nil value passed in.
	// -> PATCH request to /repos/{owner}/{repo}/code-scanning/alerts/{alert_number}
	_, resp, err = client.CodeScanning.UpdateAlert(context.Background(), *repo.Owner.Login, *repo.Name, RANDOM_INTEGER, nil)
	switch resp.StatusCode {
	case 403:
		return READ_ONLY, nil
	case 422:
		return READ_WRITE, nil
	case 200:
		log.Fatal("This should never happen. We are updating an alert with nil which should be an invalid request.")
		return READ_WRITE, nil
	default:
		return ERROR, err
	}
}

func getCodespacesPermission(client *gh.Client, repo *gh.Repository, currentAccess string) (string, error) {
	// Risk: Extremely Low
	// GET request to /repos/{owner}/{repo}/codespaces
	_, resp, err := client.Codespaces.ListInRepo(context.Background(), *repo.Owner.Login, *repo.Name, nil)
	switch resp.StatusCode {
	case 403, 404:
		return NO_ACCESS, nil
	case 200:
		break
	default:
		return ERROR, err
	}

	// Risk: Extremely Low
	// GET request to /repos/{owner}/{repo}/codespaces/permissions_check
	req, err := client.NewRequest("GET", "https://api.github.com/repos/"+*repo.Owner.Login+"/"+*repo.Name+"/codespaces/permissions_check", nil)
	if err != nil {
		return ERROR, err
	}
	resp, err = client.Do(context.Background(), req, nil)
	switch resp.StatusCode {
	case 403:
		return READ_ONLY, nil
	case 422:
		return READ_WRITE, nil
	case 200:
		return READ_WRITE, nil
	default:
		return ERROR, err
	}
}

func getCodespacesMetadataPermission(client *gh.Client, repo *gh.Repository, currentAccess string) (string, error) {
	// Risk: Extremely Low
	// GET request to /repos/{owner}/{repo}/codespaces/machines
	req, err := client.NewRequest("GET", "https://api.github.com/repos/"+*repo.Owner.Login+"/"+*repo.Name+"/codespaces/machines", nil)
	if err != nil {
		return ERROR, err
	}
	resp, err := client.Do(context.Background(), req, nil)
	switch resp.StatusCode {
	case 403:
		return NO_ACCESS, nil
	case 200:
		return READ_ONLY, nil
	default:
		return ERROR, err
	}
}

func getCodespacesSecretsPermission(client *gh.Client, repo *gh.Repository, currentAccess string) (string, error) {
	// Risk: Extremely Low
	// GET request to /repos/{owner}/{repo}/codespaces/secrets for non-existent secret
	_, resp, err := client.Codespaces.GetRepoSecret(context.Background(), *repo.Owner.Login, *repo.Name, RANDOM_STRING)
	switch resp.StatusCode {
	case 403:
		return NO_ACCESS, nil
	case 404:
		return READ_WRITE, nil
	case 200:
		return READ_WRITE, nil
	default:
		return ERROR, err
	}
}

// getCommitStatusesPermission will check if we have access to commit statuses for a given repo.
// By default, we have read-only access to commit statuses for all public repos. If only public repos exist under
// this key's permissions, then they best we can hope for us a READ_WRITE status or an UNKNOWN status.
// If a private repo exists, then we can check for READ_ONLY, READ_WRITE and NO_ACCESS.
func getCommitStatusesPermission(client *gh.Client, repo *gh.Repository, currentAccess string) (string, error) {
	if *repo.Private {
		// Risk: Extremely Low
		// GET request to /repos/{owner}/{repo}/commits/{commit_sha}/statuses
		_, resp, err := client.Repositories.ListStatuses(context.Background(), *repo.Owner.Login, *repo.Name, RANDOM_STRING, nil)
		switch resp.StatusCode {
		case 403:
			return NO_ACCESS, nil
		case 404:
			break
		default:
			return ERROR, err
		}
		// At this point we have read access

		// Risk: Extremely Low
		// -> We're POSTing a commit status to a commit that cannot exist. This should always return 422 if valid access.
		// POST request to /repos/{owner}/{repo}/statuses/{commit_sha}
		_, resp, err = client.Repositories.CreateStatus(context.Background(), *repo.Owner.Login, *repo.Name, RANDOM_STRING, &gh.RepoStatus{})
		switch resp.StatusCode {
		case 403:
			return READ_ONLY, nil
		case 422:
			return READ_WRITE, nil
		default:
			return ERROR, err
		}
	} else {
		// Will only land here if already tested one public repo and got a 403.
		if currentAccess == UNKNOWN {
			return UNKNOWN, nil
		}
		// Risk: Extremely Low
		// -> We're POSTing a commit status to a commit that cannot exist. This should always return 422 if valid access.
		// POST request to /repos/{owner}/{repo}/statuses/{commit_sha}
		_, resp, err := client.Repositories.CreateStatus(context.Background(), *repo.Owner.Login, *repo.Name, RANDOM_STRING, &gh.RepoStatus{})
		switch resp.StatusCode {
		case 403:
			// All we know is we don't have READ_WRITE
			return UNKNOWN, nil
		case 422:
			return READ_WRITE, nil
		default:
			return ERROR, err
		}
	}
}

// getContentsPermission will check if we have access to the contents of a given repo.
// By default, we have read-only access to the contents of all public repos. If only public repos exist under
// this key's permissions, then they best we can hope for us a READ_WRITE status or an UNKNOWN status.
// If a private repo exists, then we can check for READ_ONLY, READ_WRITE and NO_ACCESS.
func getContentsPermission(client *gh.Client, repo *gh.Repository, currentAccess string) (string, error) {
	if *repo.Private {
		// Risk: Extremely Low
		// GET request to /repos/{owner}/{repo}/commits
		_, resp, err := client.Repositories.ListCommits(context.Background(), *repo.Owner.Login, *repo.Name, &gh.CommitsListOptions{})
		switch resp.StatusCode {
		case 403:
			return NO_ACCESS, nil
		case 200:
			break
		case 409:
			break
		default:
			return ERROR, err
		}
		// At this point we have read access

		// Risk: Low-Medium
		// -> We're creating a file with an invalid payload. Worst case is a file with a random string and no content is created. But this should never happen.
		// PUT /repos/{owner}/{repo}/contents/{path}
		_, resp, err = client.Repositories.CreateFile(context.Background(), *repo.Owner.Login, *repo.Name, RANDOM_STRING, &gh.RepositoryContentFileOptions{})
		switch resp.StatusCode {
		case 403:
			return READ_ONLY, nil
		case 200:
			log.Fatal("This should never happen. We are creating a file with an invalid payload.")
			return READ_WRITE, nil
		case 400, 422:
			return READ_WRITE, nil
		default:
			return ERROR, err
		}
	} else {
		// Will only land here if already tested one public repo and got a 403.
		if currentAccess == UNKNOWN {
			return UNKNOWN, nil
		}
		// Risk: Low-Medium
		// -> We're creating a file with an invalid payload. Worst case is a file with a random string and no content is created. But this should never happen.
		// PUT /repos/{owner}/{repo}/contents/{path}
		_, resp, err := client.Repositories.CreateFile(context.Background(), *repo.Owner.Login, *repo.Name, RANDOM_STRING, &gh.RepositoryContentFileOptions{})
		switch resp.StatusCode {
		case 403:
			return UNKNOWN, nil
		case 200:
			log.Fatal("This should never happen. We are creating a file with an invalid payload.")
			return READ_WRITE, nil
		case 400, 422:
			return READ_WRITE, nil
		default:
			return ERROR, err
		}
	}
}

// func getCustomPropertiesPermission(client *gh.Client, owner, repo string, private bool) (string, error) {
// 	// Look for the phrase "Custom properties only supported for organizations" in the response body
// 	// If find, then we want to skip this repo.
// 	// If all repos have that phrase, then we have to put "Unknown".
//  // If we find a repo without that (an organization-owned repo), then we just check for NO_ACCESS and READ_WRITE?
//  // I'd add in READ_ONLY, but the docs only show one `write` endpoint for this block.
// }

func getDependabotAlertsPermission(client *gh.Client, repo *gh.Repository, currentAccess string) (string, error) {
	// Risk: Extremely Low
	// GET /repos/{owner}/{repo}/dependabot/alerts
	_, resp, err := client.Dependabot.ListRepoAlerts(context.Background(), *repo.Owner.Login, *repo.Name, &gh.ListAlertsOptions{})
	switch resp.StatusCode {
	case 403:
		defer resp.Body.Close()

		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Fatal(err)
		}
		body := string(bodyBytes)

		if strings.Contains(body, "Dependabot alerts are disabled for this repository.") {
			return UNKNOWN, nil
		}
		return NO_ACCESS, nil
	case 200:
		break
	default:
		return ERROR, err
	}

	// PATCH /repos/{owner}/{repo}/dependabot/alerts/{alert_number}
	_, resp, err = client.Dependabot.UpdateAlert(context.Background(), *repo.Owner.Login, *repo.Name, RANDOM_INTEGER, nil)
	switch resp.StatusCode {
	case 403:
		return READ_ONLY, nil
	case 422, 404:
		return READ_WRITE, nil
	case 200:
		log.Fatal("This should never happen. We are updating an alert with nil which should be an invalid request.")
		return READ_WRITE, nil
	default:
		return ERROR, err
	}
}

func getDependabotSecretsPermission(client *gh.Client, repo *gh.Repository, currentAccess string) (string, error) {
	// Risk: Extremely Low
	// GET /repos/{owner}/{repo}/dependabot/secrets
	_, resp, err := client.Dependabot.ListRepoSecrets(context.Background(), *repo.Owner.Login, *repo.Name, &gh.ListOptions{})
	switch resp.StatusCode {
	case 403:
		return NO_ACCESS, nil
	case 200:
		break
	default:
		return ERROR, err
	}

	// Risk: Very Low
	// -> We're "creating" a secret with an invalid payload. Even if we did, the name would be (see RANDOM_STRING above) and the value would be nil.
	// PUT /repos/{owner}/{repo}/dependabot/secrets/{secret_name}
	resp, err = client.Dependabot.CreateOrUpdateRepoSecret(context.Background(), *repo.Owner.Login, *repo.Name, &gh.DependabotEncryptedSecret{Name: RANDOM_STRING})
	switch resp.StatusCode {
	case 403:
		return READ_ONLY, nil
	case 422:
		return READ_WRITE, nil
	case 201, 204:
		log.Fatal("This should never happen. We are creating a secret with an invalid payload.")
		return READ_WRITE, nil
	default:
		return ERROR, err
	}
}

func getDeploymentsPermission(client *gh.Client, repo *gh.Repository, currentAccess string) (string, error) {
	// Risk: Extremely Low
	// GET /repos/{owner}/{repo}/deployments
	_, resp, err := client.Repositories.ListDeployments(context.Background(), *repo.Owner.Login, *repo.Name, &gh.DeploymentsListOptions{})
	switch resp.StatusCode {
	case 403:
		return NO_ACCESS, nil
	case 200:
		break
	default:
		return ERROR, err
	}

	// Risk: Very Low
	// -> We're creating a deployment with an invalid payload. Even if we did, the name would be (see RANDOM_STRING above) and the value would be nil.
	// POST /repos/{owner}/{repo}/deployments/{deployment_id}/statuses
	_, resp, err = client.Repositories.CreateDeployment(context.Background(), *repo.Owner.Login, *repo.Name, &gh.DeploymentRequest{})
	switch resp.StatusCode {
	case 403:
		return READ_ONLY, nil
	case 409, 422:
		return READ_WRITE, nil
	case 201, 202:
		log.Fatal("This should never happen. We are creating a deployment with an invalid payload.")
		return READ_WRITE, nil
	default:
		return ERROR, err
	}
}

func getEnvironmentsPermission(client *gh.Client, repo *gh.Repository, currentAccess string) (string, error) {
	// Risk: Extremely Low
	// GET /repos/{owner}/{repo}/environments
	envResp, resp, _ := client.Repositories.ListEnvironments(context.Background(), *repo.Owner.Login, *repo.Name, &gh.EnvironmentListOptions{})
	if resp.StatusCode != 200 {
		return UNKNOWN, nil
	}
	// If no environments exist, then we return UNKNOWN
	if len(envResp.Environments) == 0 {
		return UNKNOWN, nil
	}

	// Risk: Extremely Low
	// GET /repositories/{repository_id}/environments/{environment_name}/variables
	_, resp, err := client.Actions.ListEnvVariables(context.Background(), *repo.Owner.Login, *repo.Name, *envResp.Environments[0].Name, &gh.ListOptions{})
	switch resp.StatusCode {
	case 403:
		return NO_ACCESS, nil
	case 200:
		break
	default:
		return ERROR, err
	}

	// Risk: Very Low
	// -> We're updating an environment variable with an invalid payload. Even if we did, the name would be (see RANDOM_STRING above) and the value would be nil.
	// PATCH /repositories/{repository_id}/environments/{environment_name}/variables/{variable_name}
	resp, err = client.Actions.UpdateEnvVariable(context.Background(), *repo.Owner.Login, *repo.Name, *envResp.Environments[0].Name, &gh.ActionsVariable{Name: RANDOM_STRING})
	switch resp.StatusCode {
	case 403:
		return READ_ONLY, nil
	case 422:
		return READ_WRITE, nil
	case 200:
		log.Fatal("This should never happen. We are updating an environment variable with an invalid payload.")
		return READ_WRITE, nil
	default:
		return ERROR, err
	}
}

func getIssuesPermission(client *gh.Client, repo *gh.Repository, currentAccess string) (string, error) {

	if *repo.Private {

		// Risk: Extremely Low
		// GET /repos/{owner}/{repo}/issues
		_, resp, err := client.Issues.ListByRepo(context.Background(), *repo.Owner.Login, *repo.Name, &gh.IssueListByRepoOptions{})
		switch resp.StatusCode {
		case 403:
			return NO_ACCESS, nil
		case 200, 301:
			break
		default:
			return ERROR, err
		}

		// Risk: Very Low
		// -> We're editing an issue label that does not exist. Even if we did, the name would be (see RANDOM_STRING above).
		// PATCH /repos/{owner}/{repo}/labels/{name}
		_, resp, err = client.Issues.EditLabel(context.Background(), *repo.Owner.Login, *repo.Name, RANDOM_STRING, &gh.Label{})
		switch resp.StatusCode {
		case 403:
			return READ_ONLY, nil
		case 404:
			return READ_WRITE, nil
		case 200:
			log.Fatal("This should never happen. We are editing a label with an invalid payload.")
			return READ_WRITE, nil
		default:
			return ERROR, err
		}
	} else {
		// Will only land here if already tested one public repo and got a 403.
		if currentAccess == UNKNOWN {
			return UNKNOWN, nil
		}
		// Risk: Very Low
		// -> We're editing an issue label that does not exist. Even if we did, the name would be (see RANDOM_STRING above).
		// PATCH /repos/{owner}/{repo}/labels/{name}
		_, resp, err := client.Issues.EditLabel(context.Background(), *repo.Owner.Login, *repo.Name, RANDOM_STRING, &gh.Label{})
		switch resp.StatusCode {
		case 403:
			return UNKNOWN, nil
		case 404:
			return READ_WRITE, nil
		case 200:
			log.Fatal("This should never happen. We are editing a label with an invalid payload.")
			return READ_WRITE, nil
		default:
			return ERROR, err
		}
	}
}

func getPagesPermission(client *gh.Client, repo *gh.Repository, currentAccess string) (string, error) {
	if *repo.Private {
		// Risk: Extremely Low
		// GET /repos/{owner}/{repo}/pages
		_, resp, err := client.Repositories.GetPagesInfo(context.Background(), *repo.Owner.Login, *repo.Name)
		switch resp.StatusCode {
		case 403:
			return NO_ACCESS, nil
		case 200, 404:
			break
		default:
			return ERROR, err
		}

		// Risk: Very Low
		// -> We're cancelling a GitHub Pages deployment that does not exist (see RANDOM_STRING above).
		// POST /repos/{owner}/{repo}/pages/deployments/{deployment_id}/cancel
		req, err := client.NewRequest("POST", "https://api.github.com/repos/"+*repo.Owner.Login+"/"+*repo.Name+"/pages/deployments/"+RANDOM_STRING+"/cancel", nil)
		if err != nil {
			return ERROR, err
		}
		resp, err = client.Do(context.Background(), req, nil)
		switch resp.StatusCode {
		case 403:
			return READ_ONLY, nil
		case 404:
			return READ_WRITE, nil
		case 200:
			log.Fatal("This should never happen. We are cancelling a deployment with an invalid ID.")
			return READ_WRITE, nil
		default:
			return ERROR, err
		}
	} else {
		// Will only land here if already tested one public repo and got a 403.
		if currentAccess == UNKNOWN {
			return UNKNOWN, nil
		}
		// Risk: Very Low
		// -> We're cancelling a GitHub Pages deployment that does not exist (see RANDOM_STRING above).
		// POST /repos/{owner}/{repo}/pages/deployments/{deployment_id}/cancel
		req, err := client.NewRequest("POST", "https://api.github.com/repos/"+*repo.Owner.Login+"/"+*repo.Name+"/pages/deployments/"+RANDOM_STRING+"/cancel", nil)
		if err != nil {
			return ERROR, err
		}
		resp, err := client.Do(context.Background(), req, nil)
		switch resp.StatusCode {
		case 403:
			return UNKNOWN, nil
		case 404:
			return READ_WRITE, nil
		case 200:
			log.Fatal("This should never happen. We are cancelling a deployment with an invalid ID.")
			return READ_WRITE, nil
		default:
			return ERROR, err
		}
	}
}

func getPullRequestsPermission(client *gh.Client, repo *gh.Repository, currentAccess string) (string, error) {
	if *repo.Private {
		// Risk: Extremely Low
		// GET /repos/{owner}/{repo}/pulls
		_, resp, err := client.PullRequests.List(context.Background(), *repo.Owner.Login, *repo.Name, &gh.PullRequestListOptions{})
		switch resp.StatusCode {
		case 403:
			return NO_ACCESS, nil
		case 200:
			break
		default:
			return ERROR, err
		}

		// Risk: Very Low
		// -> We're creating a pull request with an invalid payload.
		// POST /repos/{owner}/{repo}/pulls
		_, resp, err = client.PullRequests.Create(context.Background(), *repo.Owner.Login, *repo.Name, &gh.NewPullRequest{})
		switch resp.StatusCode {
		case 403:
			return READ_ONLY, nil
		case 422:
			return READ_WRITE, nil
		case 200:
			log.Fatal("This should never happen. We are creating a pull request with an invalid payload.")
			return READ_WRITE, nil
		default:
			return ERROR, err
		}
	} else {
		// Will only land here if already tested one public repo and got a 403.
		if currentAccess == UNKNOWN {
			return UNKNOWN, nil
		}
		// Risk: Very Low
		// -> We're creating a pull request with an invalid payload.
		// POST /repos/{owner}/{repo}/pulls
		_, resp, err := client.PullRequests.Create(context.Background(), *repo.Owner.Login, *repo.Name, &gh.NewPullRequest{})
		switch resp.StatusCode {
		case 403:
			return UNKNOWN, nil
		case 422:
			return READ_WRITE, nil
		case 200:
			log.Fatal("This should never happen. We are creating a pull request with an invalid payload.")
			return READ_WRITE, nil
		default:
			return ERROR, err
		}
	}
}

func getRepoSecurityPermission(client *gh.Client, repo *gh.Repository, currentAccess string) (string, error) {

	if *repo.Private {
		// Risk: Extremely Low
		// GET /repos/{owner}/{repo}/security-advisories
		_, resp, err := client.SecurityAdvisories.ListRepositorySecurityAdvisories(context.Background(), *repo.Owner.Login, *repo.Name, nil)
		switch resp.StatusCode {
		case 403, 404:
			return NO_ACCESS, nil
		case 200:
			break
		default:
			return ERROR, err
		}

		// Risk: Very Low
		// -> We're creating a security advisory with an invalid payload.
		// POST /repos/{owner}/{repo}/security-advisories
		req, err := client.NewRequest("POST", "https://api.github.com/repos/"+*repo.Owner.Login+"/"+*repo.Name+"/security-advisories", nil)
		if err != nil {
			return ERROR, err
		}
		resp, err = client.Do(context.Background(), req, nil)
		switch resp.StatusCode {
		case 403:
			return READ_ONLY, nil
		case 422:
			return READ_WRITE, nil
		case 200:
			log.Fatal("This should never happen. We are creating a security advisory with an invalid payload.")
			return READ_WRITE, nil
		default:
			return ERROR, err
		}
	} else {
		// Will only land here if already tested one public repo and got a 403.
		if currentAccess == UNKNOWN {
			return UNKNOWN, nil
		}
		// Risk: Very Low
		// -> We're creating a security advisory with an invalid payload.
		// POST /repos/{owner}/{repo}/security-advisories
		req, err := client.NewRequest("POST", "https://api.github.com/repos/"+*repo.Owner.Login+"/"+*repo.Name+"/security-advisories", nil)
		if err != nil {
			return ERROR, err
		}
		resp, err := client.Do(context.Background(), req, nil)
		switch resp.StatusCode {
		case 403:
			return UNKNOWN, nil
		case 422:
			return READ_WRITE, nil
		case 200:
			log.Fatal("This should never happen. We are creating a security advisory with an invalid payload.")
			return READ_WRITE, nil
		default:
			return ERROR, err
		}
	}
}

func getSecretScanningPermission(client *gh.Client, repo *gh.Repository, currentAccess string) (string, error) {
	// Risk: Extremely Low
	// GET /repos/{owner}/{repo}/secret-scanning/alerts
	_, resp, err := client.SecretScanning.ListAlertsForRepo(context.Background(), *repo.Owner.Login, *repo.Name, nil)
	switch resp.StatusCode {
	case 403:
		return NO_ACCESS, nil
	case 200, 404:
		break
	default:
		return ERROR, err
	}

	// Risk: Very Low
	// -> We're updating a secret scanning alert for an alert that doesn't exist.
	// POST /repos/{owner}/{repo}/secret-scanning/alerts
	_, resp, err = client.SecretScanning.UpdateAlert(context.Background(), *repo.Owner.Login, *repo.Name, RANDOM_INTEGER, &gh.SecretScanningAlertUpdateOptions{})
	switch resp.StatusCode {
	case 403:
		return READ_ONLY, nil
	case 404, 422:
		return READ_WRITE, nil
	case 200:
		log.Fatal("This should never happen. We are updating a secret scanning alert that doesn't exist.")
		return READ_WRITE, nil
	default:
		return ERROR, err
	}
}

func getSecretsPermission(client *gh.Client, repo *gh.Repository, currentAccess string) (string, error) {
	// Risk: Extremely Low
	// GET /repos/{owner}/{repo}/actions/secrets
	_, resp, err := client.Actions.ListRepoSecrets(context.Background(), *repo.Owner.Login, *repo.Name, &gh.ListOptions{})
	switch resp.StatusCode {
	case 403:
		return NO_ACCESS, nil
	case 200:
		break
	default:
		return ERROR, err
	}

	// Risk: Very Low
	// -> We're creating a secret with an invalid payload.
	// PUT /repos/{owner}/{repo}/actions/secrets/{secret_name}
	resp, err = client.Actions.CreateOrUpdateRepoSecret(context.Background(), *repo.Owner.Login, *repo.Name, &gh.EncryptedSecret{Name: RANDOM_STRING})
	switch resp.StatusCode {
	case 403:
		return READ_ONLY, nil
	case 422:
		return READ_WRITE, nil
	case 201, 204:
		log.Fatal("This should never happen. We are creating a secret with an invalid payload.")
		return READ_WRITE, nil
	default:
		return ERROR, err
	}
}

func getVariablesPermission(client *gh.Client, repo *gh.Repository, currentAccess string) (string, error) {
	// Risk: Extremely Low
	// GET /repos/{owner}/{repo}/actions/variables
	_, resp, err := client.Actions.ListRepoVariables(context.Background(), *repo.Owner.Login, *repo.Name, &gh.ListOptions{})
	switch resp.StatusCode {
	case 403:
		return NO_ACCESS, nil
	case 200:
		break
	default:
		return ERROR, err
	}

	// Risk: Very Low
	// -> We're updating a variable that doesn't exist with an invalid payload.
	// PATCH /repos/{owner}/{repo}/actions/variables/{name}
	resp, err = client.Actions.UpdateRepoVariable(context.Background(), *repo.Owner.Login, *repo.Name, &gh.ActionsVariable{Name: RANDOM_STRING})
	switch resp.StatusCode {
	case 403:
		return READ_ONLY, nil
	case 422:
		return READ_WRITE, nil
	case 201, 204:
		log.Fatal("This should never happen. We are patching a variable with an invalid payload and no name.")
		return READ_WRITE, nil
	default:
		return ERROR, err
	}
}

func getWebhooksPermission(client *gh.Client, repo *gh.Repository, currentAccess string) (string, error) {
	// Risk: Extremely Low
	// GET /repos/{owner}/{repo}/hooks
	_, resp, err := client.Repositories.ListHooks(context.Background(), *repo.Owner.Login, *repo.Name, &gh.ListOptions{})
	switch resp.StatusCode {
	case 403, 404:
		return NO_ACCESS, nil
	case 200:
		break
	default:
		return ERROR, err
	}

	// Risk: Very Low
	// -> We're updating a webhook that doesn't exist with an invalid payload.
	// PATCH /repos/{owner}/{repo}/hooks/{hook_id}
	_, resp, err = client.Repositories.EditHook(context.Background(), *repo.Owner.Login, *repo.Name, RANDOM_INTEGER, &gh.Hook{})
	switch resp.StatusCode {
	case 403:
		return READ_ONLY, nil
	case 404:
		return READ_WRITE, nil
	case 200:
		log.Fatal("This should never happen. We are updating a webhook with an invalid payload.")
		return READ_WRITE, nil
	default:
		return ERROR, err
	}
}

// analyzeRepositoryPermissions will analyze the fine-grained permissions of a given permission type and return the access level.
// This function is needed b/c in some cases a token could have permissions that are only enabled on specific repos.
// If we only checked one repo, we wouldn't be able to tell if the token has access to a specific permission type.
// Ex: "Code scanning alerts" must be enabled to tell if we have that permission.
func analyzeRepositoryPermissions(client *gh.Client, repos []*gh.Repository, permissionType string) string {
	access := ""
	for _, repo := range repos {
		access, _ = repoPermFuncMap[permissionType](client, repo, access)
		if access != UNKNOWN && access != ERROR {
			return access
		}
	}
	return access
}

func getBlockUserPermission(client *gh.Client, user *gh.User) (string, error) {
	// Risk: Extremely Low
	// -> GET request to /user/blocks
	_, resp, err := client.Users.ListBlockedUsers(context.Background(), nil)
	switch resp.StatusCode {
	case 403, 404:
		return NO_ACCESS, nil
	case 200:
		break
	default:
		return ERROR, err
	}

	// Risk: Extremely Low
	// -> PUT request to /user/blocks/{username}
	// -> We're blocking a user that doesn't exist. See RANDOM_STRING above.
	resp, err = client.Users.BlockUser(context.Background(), RANDOM_STRING)
	switch resp.StatusCode {
	case 403:
		return READ_ONLY, nil
	case 404:
		return READ_WRITE, nil
	case 204:
		log.Fatal("This should never happen. We are blocking a user that doesn't exist.")
		return READ_WRITE, nil
	default:
		return ERROR, err
	}
}

func getCodespacesUserPermission(client *gh.Client, user *gh.User) (string, error) {
	// Risk: Extremely Low
	// GET request to /user/codespaces/secrets
	_, resp, err := client.Codespaces.ListUserSecrets(context.Background(), nil)
	switch resp.StatusCode {
	case 403, 404:
		return NO_ACCESS, nil
	case 200:
		break
	default:
		return ERROR, err
	}

	// Risk: Low
	// PUT request to /user/codespaces/secrets/{secret_name}
	// Payload is invalid, so it shouldn't actually post.
	resp, err = client.Codespaces.CreateOrUpdateUserSecret(context.Background(), &gh.EncryptedSecret{Name: RANDOM_STRING})
	switch resp.StatusCode {
	case 403:
		return READ_ONLY, nil
	case 422:
		return READ_WRITE, nil
	case 201, 204:
		log.Fatal("This should never happen. We are creating a user secret with an invalid payload.")
		return READ_WRITE, nil
	default:
		return ERROR, err
	}
}

func getEmailPermission(client *gh.Client, user *gh.User) (string, error) {
	// Risk: Extremely Low
	// GET request to /user/emails
	_, resp, err := client.Users.ListEmails(context.Background(), nil)
	switch resp.StatusCode {
	case 403, 404:
		return NO_ACCESS, nil
	case 200:
		break
	default:
		return ERROR, err
	}

	// Risk: Low
	// POST request to /user/emails/visibility
	_, resp, err = client.Users.SetEmailVisibility(context.Background(), RANDOM_STRING)
	switch resp.StatusCode {
	case 403, 404:
		return READ_ONLY, nil
	case 422:
		return READ_WRITE, nil
	case 201:
		log.Fatal("This should never happen. We are setting email visibility with an invalid payload.")
		return READ_WRITE, nil
	default:
		return ERROR, err
	}
}

func getFollowersPermission(client *gh.Client, user *gh.User) (string, error) {
	// Risk: Extremely Low
	// GET request to /user/followers
	_, resp, err := client.Users.ListFollowers(context.Background(), "", nil)
	switch resp.StatusCode {
	case 403:
		return NO_ACCESS, nil
	case 200:
		break
	default:
		return ERROR, err
	}

	// Risk: Low - Medium
	// DELETE request to /user/followers/{username}
	// For the username value, we need to use a real username. So there is a super small chance that someone following
	// an account for RANDOM_USERNAME value will then no longer follow that account.
	// But we're using an account created specifically for this purpose with no activity.
	resp, err = client.Users.Unfollow(context.Background(), RANDOM_USERNAME)
	switch resp.StatusCode {
	case 403, 404:
		return READ_ONLY, nil
	case 204:
		return READ_WRITE, nil
	default:
		return ERROR, err
	}
}

func getGPGKeysPermission(client *gh.Client, user *gh.User) (string, error) {
	// Risk: Extremely Low
	// GET request to /user/gpg_keys
	_, resp, err := client.Users.ListGPGKeys(context.Background(), "", nil)
	switch resp.StatusCode {
	case 403, 404:
		return NO_ACCESS, nil
	case 200:
		break
	default:
		return ERROR, err
	}

	// Risk: Low - Medium
	// POST request to /user/gpg_keys
	// Payload is invalid, so it shouldn't actually post.
	_, resp, err = client.Users.CreateGPGKey(context.Background(), RANDOM_STRING)
	switch resp.StatusCode {
	case 403:
		return READ_ONLY, nil
	case 422:
		return READ_WRITE, nil
	case 200, 201, 204:
		log.Fatal("This should never happen. We are creating a GPG key with an invalid payload.")
		return READ_WRITE, nil
	default:
		return ERROR, err
	}
}

func getGistsPermission(client *gh.Client, user *gh.User) (string, error) {
	// Risk: Low - Medium
	// POST request to /gists
	// Payload is invalid, so it shouldn't actually post.
	_, resp, err := client.Gists.Create(context.Background(), &gh.Gist{})
	switch resp.StatusCode {
	case 403, 404:
		return NO_ACCESS, nil
	case 422:
		return READ_WRITE, nil
	case 200, 201, 204:
		log.Fatal("This should never happen. We are creating a Gist with an invalid payload.")
		return READ_WRITE, nil
	default:
		return ERROR, err
	}
}

func getGitKeysPermission(client *gh.Client, user *gh.User) (string, error) {
	// Risk: Extremely Low
	// GET request to /user/keys
	_, resp, err := client.Users.ListKeys(context.Background(), "", nil)
	switch resp.StatusCode {
	case 403, 404:
		return NO_ACCESS, nil
	case 200:
		break
	default:
		return ERROR, err
	}

	// Risk: Low - Medium
	// POST request to /user/keys
	// Payload is invalid, so it shouldn't actually post.
	_, resp, err = client.Users.CreateKey(context.Background(), &gh.Key{})
	switch resp.StatusCode {
	case 403:
		return READ_ONLY, nil
	case 422:
		return READ_WRITE, nil
	case 200, 201, 204:
		log.Fatal("This should never happen. We are creating a key with an invalid payload.")
		return READ_WRITE, nil
	default:
		return ERROR, err
	}
}

func getLimitsPermission(client *gh.Client, user *gh.User) (string, error) {
	// Risk: Extremely Low
	// GET request to /user/interaction-limits
	req, err := client.NewRequest("GET", "https://api.github.com/user/interaction-limits", nil)
	if err != nil {
		return ERROR, err
	}
	resp, err := client.Do(context.Background(), req, nil)
	switch resp.StatusCode {
	case 403:
		return NO_ACCESS, nil
	case 200, 204:
		break
	default:
		return ERROR, err
	}

	// Risk: Low
	// PUT request to /user/interaction-limits
	// Payload is invalid, so it shouldn't actually post.
	req, err = client.NewRequest("PUT", "https://api.github.com/user/interaction-limits", nil)
	if err != nil {
		return ERROR, err
	}
	resp, err = client.Do(context.Background(), req, nil)
	switch resp.StatusCode {
	case 403:
		return READ_ONLY, nil
	case 422:
		return READ_WRITE, nil
	case 200, 204:
		log.Fatal("This should never happen. We are setting interaction limits with an invalid payload.")
		return READ_WRITE, nil
	default:
		return ERROR, err
	}
}

func getPlanPermission(client *gh.Client, user *gh.User) (string, error) {
	// Risk: Extremely Low
	// GET request to /user/{username}/settings/billing/actions
	_, resp, err := client.Billing.GetActionsBillingUser(context.Background(), *user.Login)
	switch resp.StatusCode {
	case 403, 404:
		return NO_ACCESS, nil
	case 200:
		return READ_ONLY, nil
	default:
		return ERROR, err
	}
}

func getProfilePermission(client *gh.Client, user *gh.User) (string, error) {
	// Risk: Low
	// POST request to /user/social_accounts
	// Payload is invalid, so it shouldn't actually patch.
	req, err := client.NewRequest("POST", "https://api.github.com/user/social_accounts", nil)
	if err != nil {
		return ERROR, err
	}
	resp, err := client.Do(context.Background(), req, nil)
	switch resp.StatusCode {
	case 403, 404:
		return NO_ACCESS, nil
	case 422:
		return READ_WRITE, nil
	case 200, 201, 204:
		log.Fatal("This should never happen. We are creating a social account with an invalid payload.")
		return READ_WRITE, nil
	default:
		return ERROR, err
	}
}

func getSigningKeysPermission(client *gh.Client, user *gh.User) (string, error) {
	// Risk: Extremely Low
	// GET request to /user/ssh_signing_keys
	_, resp, err := client.Users.ListSSHSigningKeys(context.Background(), "", nil)
	switch resp.StatusCode {
	case 403, 404:
		return NO_ACCESS, nil
	case 200:
		break
	default:
		return ERROR, err
	}

	// Risk: Low - Medium
	// POST request to /user/ssh_signing_keys
	// Payload is invalid, so it shouldn't actually post.
	_, resp, err = client.Users.CreateSSHSigningKey(context.Background(), &gh.Key{})
	switch resp.StatusCode {
	case 403:
		return READ_ONLY, nil
	case 422:
		return READ_WRITE, nil
	case 200, 201, 204:
		log.Fatal("This should never happen. We are creating a SSH key with an invalid payload.")
		return READ_WRITE, nil
	default:
		return ERROR, err
	}
}

func getStarringPermission(client *gh.Client, user *gh.User) (string, error) {
	// Note: We can't test READ_WRITE b/c Unstar() isn't working even with READ_WRITE permissions.
	// Note: GET /user/starred returns the same results regardless of permissions
	//       but since all have the same access, we'll call it READ_ONLY for now.
	return READ_ONLY, nil

}

func getWatchingPermission(client *gh.Client, user *gh.User) (string, error) {
	// Note: GET /user/subscriptions returns the same results regardless of permissions
	//       but since all have the same access, we'll call it READ_ONLY for now.
	return READ_ONLY, nil
}

func analyzeUserPermissions(client *gh.Client, user *gh.User, permissionType string) string {
	access := ""
	var err error
	access, err = acctPermFuncMap[permissionType](client, user)
	if err != nil {
		log.Fatal(err)
	}
	if access != UNKNOWN && access != ERROR {
		return access
	}
	return access
}

func analyzeFineGrainedToken(client *gh.Client, meta *TokenMetadata, shallowCheck bool) (*SecretInfo, error) {
	allRepos, err := getAllReposForUser(client)
	if err != nil {
		return nil, err
	}

	allGists, err := getAllGistsForUser(client)
	if err != nil {
		return nil, err
	}
	accessibleRepos := make([]*gh.Repository, 0)
	for _, repo := range allRepos {
		if analyzeRepositoryPermissions(client, []*gh.Repository{repo}, METADATA) != NO_ACCESS {
			accessibleRepos = append(accessibleRepos, repo)
		}
	}

	repoAccessMap := make(map[string]string)
	userAccessMap := make(map[string]string)

	if !shallowCheck {
		// Check our access
		for key := range repoPermFuncMap {
			repoAccessMap[key] = analyzeRepositoryPermissions(client, accessibleRepos, key)
		}

		// Analyze Account's Permissions
		for key := range acctPermFuncMap {
			userAccessMap[key] = analyzeUserPermissions(client, meta.User, key)
		}
	}

	return &SecretInfo{
		Metadata:        meta,
		Repos:           allRepos,
		Gists:           allGists,
		AccessibleRepos: accessibleRepos,
		RepoAccessMap:   repoAccessMap,
		UserAccessMap:   userAccessMap,
	}, nil
}

func printFineGrainedToken(cfg *config.Config, info *SecretInfo) {
	if len(info.AccessibleRepos) == 0 {
		// If no repos are accessible, then we only have read access to public repos
		color.Red("[!] Repository Access: Public Repositories (read-only)\n")
	} else {
		// Print out the repos the token can access
		color.Green(fmt.Sprintf("Found %v", len(info.AccessibleRepos)) + " Accessible Repositor(ies) \n")
		printGitHubRepos(info.AccessibleRepos)

		// Print out the access map
		printFineGrainedPermissions(info.RepoAccessMap, cfg.ShowAll, true)
	}

	printFineGrainedPermissions(info.UserAccessMap, cfg.ShowAll, false)
	printGists(info.Gists, cfg.ShowAll)
}

func printFineGrainedPermissions(accessMap map[string]string, showAll bool, repoPermissions bool) {
	permissionCount := 0
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Permission Type", "Permission" /* Add more column headers if needed */})

	// Extract keys from accessMap into slice
	keys := make([]string, 0, len(accessMap))
	for k := range accessMap {
		keys = append(keys, k)
	}
	// Sort the slice
	sort.Strings(keys)

	for _, key := range keys {
		value := accessMap[key]
		if value == NO_ACCESS || value == UNKNOWN || value == ERROR || value == NOT_IMPLEMENTED {
			// don't change permissionCount
		} else {
			permissionCount++
		}
		if !showAll && (value == NO_ACCESS || value == UNKNOWN || value == NOT_IMPLEMENTED) {
			continue
		} else {
			k, v := permissionFormatter(key, value)
			t.AppendRow([]any{k, v})
		}
	}
	var permissionType string
	if repoPermissions {
		permissionType = "Repositor(ies)"
	} else {
		permissionType = "User Account"
	}
	if permissionCount == 0 && !showAll {
		color.Red("No Permissions Found for the %v above\n\n", permissionType)
		return
	} else if permissionCount == 0 {
		color.Red("Found No Permissions for the %v above\n", permissionType)
	} else {
		color.Green(fmt.Sprintf("Found %v Permission(s) for the %v above\n", permissionCount, permissionType))
	}
	t.Render()
	fmt.Print("\n\n")
}
