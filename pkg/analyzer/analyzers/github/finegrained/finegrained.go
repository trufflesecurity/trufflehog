//go:generate generate_permissions finegrained.yaml finegrained_permissions.go finegrained

package finegrained

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/fatih/color"
	gh "github.com/google/go-github/v67/github"
	"github.com/jedib0t/go-pretty/v6/table"

	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/github/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
)

const (
	// Random values for testing
	RANDOM_STRING   = "FQ2pR.4voZg-gJfsqYKx_eLDNF_6BYhw8RL__"
	RANDOM_USERNAME = "d" + "ummy" + "acco" + "untgh" + "2024"
	RANDOM_REPO     = "te" + "st"
	RANDOM_INTEGER  = 4294967289
)

var ErrInvalid = errors.New("invalid")

var repoPermFuncMap = []func(client *gh.Client, repo *gh.Repository, currentAccess Permission) (Permission, error){
	getActionsPermission,
	getAdministrationPermission,
	getCodeScanningAlertsPermission,
	getCodespacesPermission,
	notImplementedRepoPerm, // ToDo: Implement. Docs make this look org-wide...not repo-based?
	getCodespacesMetadataPermission,
	getCodespacesSecretsPermission,
	getCommitStatusesPermission,
	getContentsPermission,
	notImplementedRepoPerm, // ToDo: Only supports orgs. Implement once have an org token.
	getDependabotAlertsPermission,
	getDependabotSecretsPermission,
	getDeploymentsPermission,
	getEnvironmentsPermission,
	getIssuesPermission,
	notImplementedRepoPerm, // Skipped until API better documented
	getMetadataPermission,
	getPagesPermission,
	getPullRequestsPermission,
	getRepoSecurityPermission,
	getSecretScanningPermission,
	getSecretsPermission,
	getVariablesPermission,
	getWebhooksPermission,
	notImplementedRepoPerm, // ToDo: Skipped b/c would require us to create a release (High Risk function)
}

var acctPermFuncMap = []func(client *gh.Client, user *gh.User) (Permission, error){
	getBlockUserPermission,
	getCodespacesUserPermission,
	getEmailPermission,
	getFollowersPermission,
	getGPGKeysPermission,
	getGistsPermission,
	getGitKeysPermission,
	getLimitsPermission,
	getPlanPermission,
	notImplementedAcctPerm, // Skipped until API better documented
	getProfilePermission,
	getSigningKeysPermission,
	getStarringPermission,
	getWatchingPermission,
}

// Define your custom formatter function
func permissionFormatter(key, val any) (string, string) {
	if perm, ok := val.(Permission); ok {
		permStr, err := perm.ToString()
		if err != nil {
			log.Fatal(fmt.Errorf("Error converting permission to string: %v", err))
		}
		var permissionStr string
		switch {
		case strings.Contains(permStr, "read"):
			permissionStr = "READ_ONLY"
		case strings.Contains(permStr, "write"):
			permissionStr = "READ_WRITE"
		default:
			permissionStr = "UNKNOWN"
		}

		switch permissionStr {
		case "READ_ONLY":
			yellow := color.New(color.FgYellow).SprintFunc()
			return yellow(key), yellow(permissionStr)
		case "READ_WRITE":
			red := color.New(color.FgGreen).SprintFunc()
			return red(key), red(permissionStr)
		case "UNKNOWN":
			blue := color.New(color.FgBlue).SprintFunc()
			return blue(key), blue(permissionStr)
		}
	}
	return fmt.Sprintf("%v", key), fmt.Sprintf("%v", val)
}

func notImplementedRepoPerm(client *gh.Client, repo *gh.Repository, currentAccess Permission) (Permission, error) {
	return NoAccess, nil
}

// notImplementedAcctPerm is a placeholder function that returns a "NOT_IMPLEMENTED" status when a GitHub account permission is not yet implemented.
func notImplementedAcctPerm(client *gh.Client, user *gh.User) (Permission, error) {
	return NoAccess, nil
}

func getMetadataPermission(client *gh.Client, repo *gh.Repository, currentAccess Permission) (Permission, error) {
	// Risk: Extremely Low
	// -> GET request to /repos/{owner}/{repo}/collaborators
	_, resp, err := client.Repositories.ListCollaborators(context.Background(), *repo.Owner.Login, *repo.Name, nil)
	if err != nil {
		if resp != nil && resp.StatusCode == 403 {
			return NoAccess, nil
		}
		return Invalid, err
	}
	// If no error, then we have read access

	return MetadataRead, nil
}

func getActionsPermission(client *gh.Client, repo *gh.Repository, currentAccess Permission) (Permission, error) {
	if *repo.Private {
		// Risk: Extremely Low
		// -> GET request to /repos/{owner}/{repo}/actions/artifacts
		_, resp, err := client.Actions.ListArtifacts(context.Background(), *repo.Owner.Login, *repo.Name, nil)
		if resp == nil {
			return Invalid, err
		}
		switch resp.StatusCode {
		case 403:
			return NoAccess, nil
		case 200:
			break
		default:
			return Invalid, err
		}

		// Risk: Very, very low.
		// -> Unless the user has a workflow file named (see RANDOM_STRING above), this will always return 404 for users with READ_WRITE permissions.
		// -> POST request to /repos/{owner}/{repo}/actions/workflows/{workflow_id}/dispatches
		resp, err = client.Actions.CreateWorkflowDispatchEventByFileName(context.Background(), *repo.Owner.Login, *repo.Name, RANDOM_STRING, gh.CreateWorkflowDispatchEventRequest{})
		if resp == nil {
			return Invalid, err
		}
		switch resp.StatusCode {
		case 403:
			return ActionsRead, nil
		case 404:
			return ActionsWrite, nil
		case 200:
			log.Fatal("This shouldn't print. We are enabling a workflow based on a random string " + RANDOM_STRING + ", which most likely doesn't exist.")
			return ActionsWrite, nil
		default:
			return Invalid, err
		}
	} else {
		// Will only land here if already tested one public repo and got a 403.
		if currentAccess == NoAccess {
			return NoAccess, nil
		}
		// Risk: Very, very low.
		// -> Unless the user has a workflow file named (see RANDOM_STRING above), this will always return 404 for users with READ_WRITE permissions.
		// -> POST request to /repos/{owner}/{repo}/actions/workflows/{workflow_id}/dispatches
		resp, err := client.Actions.CreateWorkflowDispatchEventByFileName(context.Background(), *repo.Owner.Login, *repo.Name, RANDOM_STRING, gh.CreateWorkflowDispatchEventRequest{})
		if resp == nil {
			return Invalid, err
		}
		switch resp.StatusCode {
		case 403:
			return NoAccess, nil
		case 404:
			return ActionsWrite, nil
		case 200:
			log.Fatal("This shouldn't print. We are enabling a workflow based on a random string " + RANDOM_STRING + ", which most likely doesn't exist.")
			return ActionsWrite, nil
		default:
			return Invalid, err
		}
	}
}

// Continue with the other functions using the same pattern...

func getAdministrationPermission(client *gh.Client, repo *gh.Repository, currentAccess Permission) (Permission, error) {
	// Risk: Extremely Low
	// -> GET request to /repos/{owner}/{repo}/actions/permissions
	_, resp, err := client.Repositories.GetActionsPermissions(context.Background(), *repo.Owner.Login, *repo.Name)
	if resp == nil {
		return Invalid, err
	}
	switch resp.StatusCode {
	case 403, 404:
		return NoAccess, nil
	case 200:
		break
	default:
		return Invalid, err
	}

	// Risk: Extremely Low
	// -> GET request to /repos/{owner}/{repo}/rulesets/rule-suites
	req, err := client.NewRequest("GET", "https://api.github.com/repos/"+*repo.Owner.Login+"/"+*repo.Name+"/rulesets/rule-suites", nil)
	if err != nil {
		return Invalid, err
	}
	resp, err = client.Do(context.Background(), req, nil)
	if resp == nil {
		return Invalid, err
	}
	switch resp.StatusCode {
	case 403:
		return AdministrationRead, nil
	case 200:
		return AdministrationWrite, nil
	default:
		return Invalid, err
	}
}

func getCodeScanningAlertsPermission(client *gh.Client, repo *gh.Repository, currentAccess Permission) (Permission, error) {
	// Risk: Extremely Low
	// -> GET request to /repos/{owner}/{repo}/code-scanning/alerts
	_, resp, err := client.CodeScanning.ListAlertsForRepo(context.Background(), *repo.Owner.Login, *repo.Name, nil)
	if resp == nil {
		return Invalid, err
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == 403:
		return NoAccess, nil
	case resp.StatusCode == 404:
		break
	case resp.StatusCode >= 200 && resp.StatusCode <= 299:
		break
	default:
		return Invalid, err
	}

	// Risk: Very Low
	// -> Even if user had an alert with the number (see RANDOM_INTEGER above), this should error 422 due to the nil value passed in.
	// -> PATCH request to /repos/{owner}/{repo}/code-scanning/alerts/{alert_number}
	_, resp, err = client.CodeScanning.UpdateAlert(context.Background(), *repo.Owner.Login, *repo.Name, RANDOM_INTEGER, nil)
	if resp == nil {
		return Invalid, err
	}
	switch resp.StatusCode {
	case 403:
		return CodeScanningAlertsRead, nil
	case 422:
		return CodeScanningAlertsWrite, nil
	case 200:
		log.Fatal("This should never happen. We are updating an alert with nil which should be an invalid request.")
		return CodeScanningAlertsWrite, nil
	default:
		return Invalid, err
	}
}

func getCodespacesPermission(client *gh.Client, repo *gh.Repository, currentAccess Permission) (Permission, error) {
	// Risk: Extremely Low
	// GET request to /repos/{owner}/{repo}/codespaces
	_, resp, err := client.Codespaces.ListInRepo(context.Background(), *repo.Owner.Login, *repo.Name, nil)
	if resp == nil {
		return Invalid, err
	}
	switch resp.StatusCode {
	case 403, 404:
		return NoAccess, nil
	case 200:
		break
	default:
		return Invalid, err
	}

	// Risk: Extremely Low
	// GET request to /repos/{owner}/{repo}/codespaces/permissions_check
	req, err := client.NewRequest("GET", "https://api.github.com/repos/"+*repo.Owner.Login+"/"+*repo.Name+"/codespaces/permissions_check", nil)
	if err != nil {
		return Invalid, err
	}
	resp, err = client.Do(context.Background(), req, nil)
	if resp == nil {
		return Invalid, err
	}
	switch resp.StatusCode {
	case 403:
		return CodespacesRead, nil
	case 422:
		return CodespacesWrite, nil
	case 200:
		return CodespacesWrite, nil
	default:
		return Invalid, err
	}
}

func getCodespacesMetadataPermission(client *gh.Client, repo *gh.Repository, currentAccess Permission) (Permission, error) {
	// Risk: Extremely Low
	// GET request to /repos/{owner}/{repo}/codespaces/machines
	req, err := client.NewRequest("GET", "https://api.github.com/repos/"+*repo.Owner.Login+"/"+*repo.Name+"/codespaces/machines", nil)
	if err != nil {
		return Invalid, err
	}
	resp, err := client.Do(context.Background(), req, nil)
	if resp == nil {
		return Invalid, err
	}
	switch resp.StatusCode {
	case 403:
		return NoAccess, nil
	case 200:
		return CodespacesMetadataRead, nil
	default:
		return Invalid, err
	}
}

func getCodespacesSecretsPermission(client *gh.Client, repo *gh.Repository, currentAccess Permission) (Permission, error) {
	// Risk: Extremely Low
	// GET request to /repos/{owner}/{repo}/codespaces/secrets for non-existent secret
	_, resp, err := client.Codespaces.GetRepoSecret(context.Background(), *repo.Owner.Login, *repo.Name, RANDOM_STRING)
	if resp == nil {
		return Invalid, err
	}
	switch resp.StatusCode {
	case 403:
		return NoAccess, nil
	case 404:
		return CodespacesSecretsWrite, nil
	case 200:
		return CodespacesSecretsWrite, nil
	default:
		return Invalid, err
	}
}

// getCommitStatusesPermission will check if we have access to commit statuses for a given repo.
// By default, we have read-only access to commit statuses for all public repos. If only public repos exist under
// this key's permissions, then they best we can hope for us a READ_WRITE status or an UNKNOWN status.
// If a private repo exists, then we can check for READ_ONLY, READ_WRITE and NO_ACCESS.
func getCommitStatusesPermission(client *gh.Client, repo *gh.Repository, currentAccess Permission) (Permission, error) {
	if *repo.Private {
		// Risk: Extremely Low
		// GET request to /repos/{owner}/{repo}/commits/{commit_sha}/statuses
		_, resp, err := client.Repositories.ListStatuses(context.Background(), *repo.Owner.Login, *repo.Name, RANDOM_STRING, nil)
		if resp == nil {
			return Invalid, err
		}
		switch resp.StatusCode {
		case 403:
			return NoAccess, nil
		case 404:
			break
		default:
			return Invalid, err
		}
		// At this point we have read access

		// Risk: Extremely Low
		// -> We're POSTing a commit status to a commit that cannot exist. This should always return 422 if valid access.
		// POST request to /repos/{owner}/{repo}/statuses/{commit_sha}
		_, resp, err = client.Repositories.CreateStatus(context.Background(), *repo.Owner.Login, *repo.Name, RANDOM_STRING, &gh.RepoStatus{})
		if resp == nil {
			return Invalid, err
		}
		switch resp.StatusCode {
		case 403:
			return CommitStatusesRead, nil
		case 422:
			return CommitStatusesWrite, nil
		default:
			return Invalid, err
		}
	} else {
		// Will only land here if already tested one public repo and got a 403.
		if currentAccess == NoAccess {
			return NoAccess, nil
		}
		// Risk: Extremely Low
		// -> We're POSTing a commit status to a commit that cannot exist. This should always return 422 if valid access.
		// POST request to /repos/{owner}/{repo}/statuses/{commit_sha}
		_, resp, err := client.Repositories.CreateStatus(context.Background(), *repo.Owner.Login, *repo.Name, RANDOM_STRING, &gh.RepoStatus{})
		if resp == nil {
			return Invalid, err
		}
		switch resp.StatusCode {
		case 403:
			// All we know is we don't have READ_WRITE
			return NoAccess, nil
		case 422:
			return CommitStatusesWrite, nil
		default:
			return Invalid, err
		}
	}
}

// getContentsPermission will check if we have access to the contents of a given repo.
// By default, we have read-only access to the contents of all public repos. If only public repos exist under
// this key's permissions, then they best we can hope for us a READ_WRITE status or an UNKNOWN status.
// If a private repo exists, then we can check for READ_ONLY, READ_WRITE and NO_ACCESS.
func getContentsPermission(client *gh.Client, repo *gh.Repository, currentAccess Permission) (Permission, error) {
	if *repo.Private {
		// Risk: Extremely Low
		// GET request to /repos/{owner}/{repo}/commits
		_, resp, err := client.Repositories.ListCommits(context.Background(), *repo.Owner.Login, *repo.Name, &gh.CommitsListOptions{})
		if resp == nil {
			return Invalid, err
		}
		switch resp.StatusCode {
		case 403:
			return NoAccess, nil
		case 200:
			break
		case 409:
			break
		default:
			return Invalid, err
		}
		// At this point we have read access

		// Risk: Low-Medium
		// -> We're creating a file with an invalid payload. Worst case is a file with a random string and no content is created. But this should never happen.
		// PUT /repos/{owner}/{repo}/contents/{path}
		_, resp, err = client.Repositories.CreateFile(context.Background(), *repo.Owner.Login, *repo.Name, RANDOM_STRING, &gh.RepositoryContentFileOptions{})
		if resp == nil {
			return Invalid, err
		}
		switch resp.StatusCode {
		case 403:
			return ContentsRead, nil
		case 200:
			log.Fatal("This should never happen. We are creating a file with an invalid payload.")
			return ContentsWrite, nil
		case 400, 422:
			return ContentsWrite, nil
		default:
			return Invalid, err
		}
	} else {
		// Will only land here if already tested one public repo and got a 403.
		if currentAccess == NoAccess {
			return NoAccess, nil
		}
		// Risk: Low-Medium
		// -> We're creating a file with an invalid payload. Worst case is a file with a random string and no content is created. But this should never happen.
		// PUT /repos/{owner}/{repo}/contents/{path}
		_, resp, err := client.Repositories.CreateFile(context.Background(), *repo.Owner.Login, *repo.Name, RANDOM_STRING, &gh.RepositoryContentFileOptions{})
		if resp == nil {
			return Invalid, err
		}
		switch resp.StatusCode {
		case 403:
			return NoAccess, nil
		case 200:
			panic("This should never happen. We are creating a file with an invalid payload.")
		case 400, 422:
			return ContentsWrite, nil
		default:
			return Invalid, err
		}
	}
}

func getDependabotAlertsPermission(client *gh.Client, repo *gh.Repository, currentAccess Permission) (Permission, error) {
	// Risk: Extremely Low
	// GET /repos/{owner}/{repo}/dependabot/alerts
	_, resp, err := client.Dependabot.ListRepoAlerts(context.Background(), *repo.Owner.Login, *repo.Name, &gh.ListAlertsOptions{})
	if resp == nil {
		return Invalid, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case 403:
		return NoAccess, nil
	case 200:
		break
	default:
		return Invalid, err
	}

	// PATCH /repos/{owner}/{repo}/dependabot/alerts/{alert_number}
	_, resp, err = client.Dependabot.UpdateAlert(context.Background(), *repo.Owner.Login, *repo.Name, RANDOM_INTEGER, nil)
	if resp == nil {
		return Invalid, err
	}
	switch resp.StatusCode {
	case 403:
		return DependabotAlertsRead, nil
	case 422, 404:
		return DependabotAlertsWrite, nil
	case 200:
		log.Fatal("This should never happen. We are updating an alert with nil which should be an invalid request.")
		return DependabotAlertsWrite, nil
	default:
		return Invalid, err
	}
}

func getDependabotSecretsPermission(client *gh.Client, repo *gh.Repository, currentAccess Permission) (Permission, error) {
	// Risk: Extremely Low
	// GET /repos/{owner}/{repo}/dependabot/secrets
	_, resp, err := client.Dependabot.ListRepoSecrets(context.Background(), *repo.Owner.Login, *repo.Name, &gh.ListOptions{})
	if resp == nil {
		return Invalid, err
	}
	switch resp.StatusCode {
	case 403:
		return NoAccess, nil
	case 200:
		break
	default:
		return Invalid, err
	}

	// Risk: Very Low
	// -> We're "creating" a secret with an invalid payload. Even if we did, the name would be (see RANDOM_STRING above) and the value would be nil.
	// PUT /repos/{owner}/{repo}/dependabot/secrets/{secret_name}
	resp, err = client.Dependabot.CreateOrUpdateRepoSecret(context.Background(), *repo.Owner.Login, *repo.Name, &gh.DependabotEncryptedSecret{Name: RANDOM_STRING})
	if resp == nil {
		return Invalid, err
	}
	switch resp.StatusCode {
	case 403:
		return DependabotSecretsRead, nil
	case 422:
		return DependabotSecretsWrite, nil
	case 201, 204:
		log.Fatal("This should never happen. We are creating a secret with an invalid payload.")
		return DependabotSecretsWrite, nil
	default:
		return Invalid, err
	}
}

func getDeploymentsPermission(client *gh.Client, repo *gh.Repository, currentAccess Permission) (Permission, error) {
	// Risk: Extremely Low
	// GET /repos/{owner}/{repo}/deployments
	_, resp, err := client.Repositories.ListDeployments(context.Background(), *repo.Owner.Login, *repo.Name, &gh.DeploymentsListOptions{})
	if resp == nil {
		return Invalid, err
	}
	switch resp.StatusCode {
	case 403:
		return NoAccess, nil
	case 200:
		break
	default:
		return Invalid, err
	}

	// Risk: Very Low
	// -> We're creating a deployment with an invalid payload. Even if we did, the name would be (see RANDOM_STRING above) and the value would be nil.
	// POST /repos/{owner}/{repo}/deployments/{deployment_id}/statuses
	_, resp, err = client.Repositories.CreateDeployment(context.Background(), *repo.Owner.Login, *repo.Name, &gh.DeploymentRequest{})
	if resp == nil {
		return Invalid, err
	}
	switch resp.StatusCode {
	case 403:
		return DeploymentsRead, nil
	case 409, 422:
		return DeploymentsWrite, nil
	case 201, 202:
		log.Fatal("This should never happen. We are creating a deployment with an invalid payload.")
		return DeploymentsWrite, nil
	default:
		return Invalid, err
	}
}

func getEnvironmentsPermission(client *gh.Client, repo *gh.Repository, currentAccess Permission) (Permission, error) {
	// Risk: Extremely Low
	// GET /repos/{owner}/{repo}/environments
	envResp, resp, _ := client.Repositories.ListEnvironments(context.Background(), *repo.Owner.Login, *repo.Name, &gh.EnvironmentListOptions{})
	if resp == nil || resp.StatusCode != 200 {
		return NoAccess, nil
	}
	// If no environments exist, then we return UNKNOWN
	if len(envResp.Environments) == 0 {
		return NoAccess, nil
	}

	// Risk: Extremely Low
	// GET /repositories/{repository_id}/environments/{environment_name}/variables
	_, resp, _ = client.Actions.ListEnvVariables(context.Background(), *repo.Owner.Login, *repo.Name, *envResp.Environments[0].Name, &gh.ListOptions{})
	if resp == nil {
		return Invalid, nil
	}
	switch resp.StatusCode {
	case 403:
		return NoAccess, nil
	case 200:
		break
	default:
		return Invalid, nil
	}

	// Risk: Very Low
	// -> We're updating an environment variable with an invalid payload. Even if we did, the name would be (see RANDOM_STRING above) and the value would be nil.
	// PATCH /repositories/{repository_id}/environments/{environment_name}/variables/{variable_name}
	resp, err := client.Actions.UpdateEnvVariable(context.Background(), *repo.Owner.Login, *repo.Name, *envResp.Environments[0].Name, &gh.ActionsVariable{Name: RANDOM_STRING})
	if resp == nil {
		return Invalid, err
	}
	switch resp.StatusCode {
	case 403:
		return EnvironmentsRead, nil
	case 422:
		return EnvironmentsWrite, nil
	case 200:
		log.Fatal("This should never happen. We are updating an environment variable with an invalid payload.")
		return EnvironmentsWrite, nil
	default:
		return Invalid, err
	}
}

func getIssuesPermission(client *gh.Client, repo *gh.Repository, currentAccess Permission) (Permission, error) {

	if *repo.Private {

		// Risk: Extremely Low
		// GET /repos/{owner}/{repo}/issues
		_, resp, err := client.Issues.ListByRepo(context.Background(), *repo.Owner.Login, *repo.Name, &gh.IssueListByRepoOptions{})
		if resp == nil {
			return Invalid, err
		}
		switch resp.StatusCode {
		case 403:
			return NoAccess, nil
		case 200, 301:
			break
		default:
			return Invalid, err
		}

		// Risk: Very Low
		// -> We're editing an issue label that does not exist. Even if we did, the name would be (see RANDOM_STRING above).
		// PATCH /repos/{owner}/{repo}/labels/{name}
		_, resp, err = client.Issues.EditLabel(context.Background(), *repo.Owner.Login, *repo.Name, RANDOM_STRING, &gh.Label{})
		if resp == nil {
			return Invalid, err
		}
		switch resp.StatusCode {
		case 403:
			return IssuesRead, nil
		case 404:
			return IssuesWrite, nil
		case 200:
			log.Fatal("This should never happen. We are editing a label with an invalid payload.")
			return IssuesWrite, nil
		default:
			return Invalid, err
		}
	} else {
		// Will only land here if already tested one public repo and got a 403.
		if currentAccess == NoAccess {
			return NoAccess, nil
		}
		// Risk: Very Low
		// -> We're editing an issue label that does not exist. Even if we did, the name would be (see RANDOM_STRING above).
		// PATCH /repos/{owner}/{repo}/labels/{name}
		_, resp, err := client.Issues.EditLabel(context.Background(), *repo.Owner.Login, *repo.Name, RANDOM_STRING, &gh.Label{})
		if resp == nil {
			return Invalid, err
		}
		switch resp.StatusCode {
		case 403:
			return NoAccess, nil
		case 404:
			return IssuesWrite, nil
		case 200:
			log.Fatal("This should never happen. We are editing a label with an invalid payload.")
			return IssuesWrite, nil
		default:
			return Invalid, err
		}
	}
}

func getPagesPermission(client *gh.Client, repo *gh.Repository, currentAccess Permission) (Permission, error) {
	if *repo.Private {
		// Risk: Extremely Low
		// GET /repos/{owner}/{repo}/pages
		_, resp, err := client.Repositories.GetPagesInfo(context.Background(), *repo.Owner.Login, *repo.Name)
		if resp == nil {
			return Invalid, err
		}
		switch resp.StatusCode {
		case 403:
			return NoAccess, nil
		case 200, 404:
			break
		default:
			return Invalid, err
		}

		// Risk: Very Low
		// -> We're cancelling a GitHub Pages deployment that does not exist (see RANDOM_STRING above).
		// POST /repos/{owner}/{repo}/pages/deployments/{deployment_id}/cancel
		req, err := client.NewRequest("POST", "https://api.github.com/repos/"+*repo.Owner.Login+"/"+*repo.Name+"/pages/deployments/"+RANDOM_STRING+"/cancel", nil)
		if err != nil {
			return Invalid, err
		}
		resp, err = client.Do(context.Background(), req, nil)
		if resp == nil {
			return Invalid, err
		}
		switch resp.StatusCode {
		case 403:
			return PagesRead, nil
		case 404:
			return PagesWrite, nil
		case 200:
			log.Fatal("This should never happen. We are cancelling a deployment with an invalid ID.")
			return PagesWrite, nil
		default:
			return Invalid, err
		}
	} else {
		// Will only land here if already tested one public repo and got a 403.
		if currentAccess == NoAccess {
			return NoAccess, nil
		}
		// Risk: Very Low
		// -> We're cancelling a GitHub Pages deployment that does not exist (see RANDOM_STRING above).
		// POST /repos/{owner}/{repo}/pages/deployments/{deployment_id}/cancel
		req, err := client.NewRequest("POST", "https://api.github.com/repos/"+*repo.Owner.Login+"/"+*repo.Name+"/pages/deployments/"+RANDOM_STRING+"/cancel", nil)
		if err != nil {
			return Invalid, err
		}
		resp, err := client.Do(context.Background(), req, nil)
		if resp == nil {
			return Invalid, err
		}
		switch resp.StatusCode {
		case 403:
			return NoAccess, nil
		case 404:
			return PagesWrite, nil
		case 200:
			log.Fatal("This should never happen. We are cancelling a deployment with an invalid ID.")
			return PagesWrite, nil
		default:
			return Invalid, err
		}
	}
}

func getPullRequestsPermission(client *gh.Client, repo *gh.Repository, currentAccess Permission) (Permission, error) {
	if *repo.Private {
		// Risk: Extremely Low
		// GET /repos/{owner}/{repo}/pulls
		_, resp, err := client.PullRequests.List(context.Background(), *repo.Owner.Login, *repo.Name, &gh.PullRequestListOptions{})
		if resp == nil {
			return Invalid, err
		}
		switch resp.StatusCode {
		case 403:
			return NoAccess, nil
		case 200:
			break
		default:
			return Invalid, err
		}

		// Risk: Very Low
		// -> We're creating a pull request with an invalid payload.
		// POST /repos/{owner}/{repo}/pulls
		_, resp, err = client.PullRequests.Create(context.Background(), *repo.Owner.Login, *repo.Name, &gh.NewPullRequest{})
		if resp == nil {
			return Invalid, err
		}
		switch resp.StatusCode {
		case 403:
			return PullRequestsRead, nil
		case 422:
			return PullRequestsWrite, nil
		case 200:
			log.Fatal("This should never happen. We are creating a pull request with an invalid payload.")
			return PullRequestsWrite, nil
		default:
			return Invalid, err
		}
	} else {
		// Will only land here if already tested one public repo and got a 403.
		if currentAccess == NoAccess {
			return NoAccess, nil
		}
		// Risk: Very Low
		// -> We're creating a pull request with an invalid payload.
		// POST /repos/{owner}/{repo}/pulls
		_, resp, err := client.PullRequests.Create(context.Background(), *repo.Owner.Login, *repo.Name, &gh.NewPullRequest{})
		if resp == nil {
			return Invalid, err
		}
		switch resp.StatusCode {
		case 403:
			return NoAccess, nil
		case 422:
			return PullRequestsWrite, nil
		case 200:
			log.Fatal("This should never happen. We are creating a pull request with an invalid payload.")
			return PullRequestsWrite, nil
		default:
			return Invalid, err
		}
	}
}

func getRepoSecurityPermission(client *gh.Client, repo *gh.Repository, currentAccess Permission) (Permission, error) {

	if *repo.Private {
		// Risk: Extremely Low
		// GET /repos/{owner}/{repo}/security-advisories
		_, resp, err := client.SecurityAdvisories.ListRepositorySecurityAdvisories(context.Background(), *repo.Owner.Login, *repo.Name, nil)
		if resp == nil {
			return Invalid, err
		}
		switch resp.StatusCode {
		case 403, 404:
			return NoAccess, nil
		case 200:
			break
		default:
			return Invalid, err
		}

		// Risk: Very Low
		// -> We're creating a security advisory with an invalid payload.
		// POST /repos/{owner}/{repo}/security-advisories
		req, err := client.NewRequest("POST", "https://api.github.com/repos/"+*repo.Owner.Login+"/"+*repo.Name+"/security-advisories", nil)
		if err != nil {
			return Invalid, err
		}
		resp, err = client.Do(context.Background(), req, nil)
		if resp == nil {
			return Invalid, err
		}
		switch resp.StatusCode {
		case 403:
			return RepoSecurityRead, nil
		case 422:
			return RepoSecurityWrite, nil
		case 200:
			log.Fatal("This should never happen. We are creating a security advisory with an invalid payload.")
			return RepoSecurityWrite, nil
		default:
			return Invalid, err
		}
	} else {
		// Will only land here if already tested one public repo and got a 403.
		if currentAccess == NoAccess {
			return NoAccess, nil
		}
		// Risk: Very Low
		// -> We're creating a security advisory with an invalid payload.
		// POST /repos/{owner}/{repo}/security-advisories
		req, err := client.NewRequest("POST", "https://api.github.com/repos/"+*repo.Owner.Login+"/"+*repo.Name+"/security-advisories", nil)
		if err != nil {
			return Invalid, err
		}
		resp, err := client.Do(context.Background(), req, nil)
		if resp == nil {
			return Invalid, err
		}
		switch resp.StatusCode {
		case 403:
			return NoAccess, nil
		case 422:
			return RepoSecurityWrite, nil
		case 200:
			log.Fatal("This should never happen. We are creating a security advisory with an invalid payload.")
			return RepoSecurityWrite, nil
		default:
			return Invalid, err
		}
	}
}

func getSecretScanningPermission(client *gh.Client, repo *gh.Repository, currentAccess Permission) (Permission, error) {
	// Risk: Extremely Low
	// GET /repos/{owner}/{repo}/secret-scanning/alerts
	_, resp, err := client.SecretScanning.ListAlertsForRepo(context.Background(), *repo.Owner.Login, *repo.Name, nil)
	if resp == nil {
		return Invalid, err
	}
	switch resp.StatusCode {
	case 403:
		return NoAccess, nil
	case 200, 404:
		break
	default:
		return Invalid, err
	}

	// Risk: Very Low
	// -> We're updating a secret scanning alert for an alert that doesn't exist.
	// POST /repos/{owner}/{repo}/secret-scanning/alerts
	_, resp, err = client.SecretScanning.UpdateAlert(context.Background(), *repo.Owner.Login, *repo.Name, RANDOM_INTEGER, &gh.SecretScanningAlertUpdateOptions{})
	if resp == nil {
		return Invalid, err
	}
	switch resp.StatusCode {
	case 403:
		return SecretScanningRead, nil
	case 404, 422:
		return SecretScanningWrite, nil
	case 200:
		log.Fatal("This should never happen. We are updating a secret scanning alert that doesn't exist.")
		return SecretScanningWrite, nil
	default:
		return Invalid, err
	}
}

func getSecretsPermission(client *gh.Client, repo *gh.Repository, currentAccess Permission) (Permission, error) {
	// Risk: Extremely Low
	// GET /repos/{owner}/{repo}/actions/secrets
	_, resp, err := client.Actions.ListRepoSecrets(context.Background(), *repo.Owner.Login, *repo.Name, &gh.ListOptions{})
	if resp == nil {
		return Invalid, err
	}
	switch resp.StatusCode {
	case 403:
		return NoAccess, nil
	case 200:
		break
	default:
		return Invalid, err
	}

	// Risk: Very Low
	// -> We're creating a secret with an invalid payload.
	// PUT /repos/{owner}/{repo}/actions/secrets/{secret_name}
	resp, err = client.Actions.CreateOrUpdateRepoSecret(context.Background(), *repo.Owner.Login, *repo.Name, &gh.EncryptedSecret{Name: RANDOM_STRING})
	if resp == nil {
		return Invalid, err
	}
	switch resp.StatusCode {
	case 403:
		return SecretsRead, nil
	case 422:
		return SecretsWrite, nil
	case 201, 204:
		log.Fatal("This should never happen. We are creating a secret with an invalid payload.")
		return SecretsWrite, nil
	default:
		return Invalid, err
	}
}

func getVariablesPermission(client *gh.Client, repo *gh.Repository, currentAccess Permission) (Permission, error) {
	// Risk: Extremely Low
	// GET /repos/{owner}/{repo}/actions/variables
	_, resp, err := client.Actions.ListRepoVariables(context.Background(), *repo.Owner.Login, *repo.Name, &gh.ListOptions{})
	if resp == nil {
		return Invalid, err
	}
	switch resp.StatusCode {
	case 403:
		return NoAccess, nil
	case 200:
		break
	default:
		return Invalid, err
	}

	// Risk: Very Low
	// -> We're updating a variable that doesn't exist with an invalid payload.
	// PATCH /repos/{owner}/{repo}/actions/variables/{name}
	resp, err = client.Actions.UpdateRepoVariable(context.Background(), *repo.Owner.Login, *repo.Name, &gh.ActionsVariable{Name: RANDOM_STRING})
	if resp == nil {
		return Invalid, err
	}
	switch resp.StatusCode {
	case 403:
		return VariablesRead, nil
	case 422:
		return VariablesWrite, nil
	case 201, 204:
		log.Fatal("This should never happen. We are patching a variable with an invalid payload and no name.")
		return VariablesWrite, nil
	default:
		return Invalid, err
	}
}

func getWebhooksPermission(client *gh.Client, repo *gh.Repository, currentAccess Permission) (Permission, error) {
	// Risk: Extremely Low
	// GET /repos/{owner}/{repo}/hooks
	_, resp, err := client.Repositories.ListHooks(context.Background(), *repo.Owner.Login, *repo.Name, &gh.ListOptions{})
	if resp == nil {
		return Invalid, err
	}
	switch resp.StatusCode {
	case 403, 404:
		return NoAccess, nil
	case 200:
		break
	default:
		return Invalid, err
	}

	// Risk: Very Low
	// -> We're updating a webhook that doesn't exist with an invalid payload.
	// PATCH /repos/{owner}/{repo}/hooks/{hook_id}
	_, resp, err = client.Repositories.EditHook(context.Background(), *repo.Owner.Login, *repo.Name, RANDOM_INTEGER, &gh.Hook{})
	if resp == nil {
		return Invalid, err
	}
	switch resp.StatusCode {
	case 403:
		return WebhooksRead, nil
	case 404:
		return WebhooksWrite, nil
	case 200:
		log.Fatal("This should never happen. We are updating a webhook with an invalid payload.")
		return WebhooksWrite, nil
	default:
		return Invalid, err
	}
}

// analyzeRepositoryPermissions will analyze the fine-grained permissions of a given permission type and return the access level.
// This function is needed b/c in some cases a token could have permissions that are only enabled on specific repos.
// If we only checked one repo, we wouldn't be able to tell if the token has access to a specific permission type.
// Ex: "Code scanning alerts" must be enabled to tell if we have that permission.
func analyzeRepositoryPermissions(client *gh.Client, repos []*gh.Repository) ([]Permission, error) {
	perms := make([]Permission, len(repoPermFuncMap))
	for _, repo := range repos {
		for i, permFunc := range repoPermFuncMap {
			access, err := permFunc(client, repo, perms[i])
			if err != nil || access == Invalid {
				// TODO: Log error.
				continue
			}
			if perms[i] == Invalid || perms[i] == NoAccess {
				perms[i] = access
			}
		}
	}
	return perms, nil
}

func getBlockUserPermission(client *gh.Client, user *gh.User) (Permission, error) {
	// Risk: Extremely Low
	// -> GET request to /user/blocks
	_, resp, err := client.Users.ListBlockedUsers(context.Background(), nil)
	if resp == nil {
		return Invalid, err
	}
	switch resp.StatusCode {
	case 403, 404:
		return NoAccess, nil
	case 200:
		break
	default:
		return Invalid, err
	}

	// Risk: Extremely Low
	// -> PUT request to /user/blocks/{username}
	// -> We're blocking a user that doesn't exist. See RANDOM_STRING above.
	resp, err = client.Users.BlockUser(context.Background(), RANDOM_STRING)
	if resp == nil {
		return Invalid, err
	}
	switch resp.StatusCode {
	case 403:
		return BlockUserRead, nil
	case 404:
		return BlockUserWrite, nil
	case 204:
		log.Fatal("This should never happen. We are blocking a user that doesn't exist.")
		return BlockUserWrite, nil
	default:
		return Invalid, err
	}
}

func getCodespacesUserPermission(client *gh.Client, user *gh.User) (Permission, error) {
	// Risk: Extremely Low
	// GET request to /user/codespaces/secrets
	_, resp, err := client.Codespaces.ListUserSecrets(context.Background(), nil)
	if resp == nil {
		return Invalid, err
	}
	switch resp.StatusCode {
	case 403, 404:
		return NoAccess, nil
	case 200:
		break
	default:
		return Invalid, err
	}

	// Risk: Low
	// PUT request to /user/codespaces/secrets/{secret_name}
	// Payload is invalid, so it shouldn't actually post.
	resp, err = client.Codespaces.CreateOrUpdateUserSecret(context.Background(), &gh.EncryptedSecret{Name: RANDOM_STRING})
	if resp == nil {
		return Invalid, err
	}
	switch resp.StatusCode {
	case 403:
		return CodespaceUserSecretsRead, nil
	case 422:
		return CodespaceUserSecretsWrite, nil
	case 201, 204:
		log.Fatal("This should never happen. We are creating a user secret with an invalid payload.")
		return CodespaceUserSecretsWrite, nil
	default:
		return Invalid, err
	}
}

func getEmailPermission(client *gh.Client, user *gh.User) (Permission, error) {
	// Risk: Extremely Low
	// GET request to /user/emails
	_, resp, err := client.Users.ListEmails(context.Background(), nil)
	if resp == nil {
		return Invalid, err
	}
	switch resp.StatusCode {
	case 403, 404:
		return NoAccess, nil
	case 200:
		break
	default:
		return Invalid, err
	}

	// Risk: Low
	// POST request to /user/emails/visibility
	_, resp, err = client.Users.SetEmailVisibility(context.Background(), RANDOM_STRING)
	if resp == nil {
		return Invalid, err
	}
	switch resp.StatusCode {
	case 403, 404:
		return EmailRead, nil
	case 422:
		return EmailWrite, nil
	case 201:
		log.Fatal("This should never happen. We are setting email visibility with an invalid payload.")
		return EmailWrite, nil
	default:
		return Invalid, err
	}
}

func getFollowersPermission(client *gh.Client, user *gh.User) (Permission, error) {
	// Risk: Extremely Low
	// GET request to /user/followers
	_, resp, err := client.Users.ListFollowers(context.Background(), "", nil)
	if resp == nil {
		return Invalid, err
	}
	switch resp.StatusCode {
	case 403:
		return NoAccess, nil
	case 200:
		break
	default:
		return Invalid, err
	}

	// Risk: Low - Medium
	// DELETE request to /user/followers/{username}
	// For the username value, we need to use a real username. So there is a super small chance that someone following
	// an account for RANDOM_USERNAME value will then no longer follow that account.
	// But we're using an account created specifically for this purpose with no activity.
	resp, err = client.Users.Unfollow(context.Background(), RANDOM_USERNAME)
	if resp == nil {
		return Invalid, err
	}
	switch resp.StatusCode {
	case 403, 404:
		return FollowersRead, nil
	case 204:
		return FollowersWrite, nil
	default:
		return Invalid, err
	}
}

func getGPGKeysPermission(client *gh.Client, user *gh.User) (Permission, error) {
	// Risk: Extremely Low
	// GET request to /user/gpg_keys
	_, resp, err := client.Users.ListGPGKeys(context.Background(), "", nil)
	if resp == nil {
		return Invalid, err
	}
	switch resp.StatusCode {
	case 403, 404:
		return NoAccess, nil
	case 200:
		break
	default:
		return Invalid, err
	}

	// Risk: Low - Medium
	// POST request to /user/gpg_keys
	// Payload is invalid, so it shouldn't actually post.
	_, resp, err = client.Users.CreateGPGKey(context.Background(), RANDOM_STRING)
	if resp == nil {
		return Invalid, err
	}
	switch resp.StatusCode {
	case 403:
		return GpgKeysRead, nil
	case 422:
		return GpgKeysWrite, nil
	case 200, 201, 204:
		log.Fatal("This should never happen. We are creating a GPG key with an invalid payload.")
		return GpgKeysWrite, nil
	default:
		return Invalid, err
	}
}

func getGistsPermission(client *gh.Client, user *gh.User) (Permission, error) {
	// Risk: Low - Medium
	// POST request to /gists
	// Payload is invalid, so it shouldn't actually post.
	_, resp, err := client.Gists.Create(context.Background(), &gh.Gist{})
	if resp == nil {
		return Invalid, err
	}
	switch resp.StatusCode {
	case 403, 404:
		return NoAccess, nil
	case 422:
		return GistsWrite, nil
	case 200, 201, 204:
		log.Fatal("This should never happen. We are creating a Gist with an invalid payload.")
		return GistsWrite, nil
	default:
		return Invalid, err
	}
}

func getGitKeysPermission(client *gh.Client, user *gh.User) (Permission, error) {
	// Risk: Extremely Low
	// GET request to /user/keys
	_, resp, err := client.Users.ListKeys(context.Background(), "", nil)
	if resp == nil {
		return Invalid, err
	}
	switch resp.StatusCode {
	case 403, 404:
		return NoAccess, nil
	case 200:
		break
	default:
		return Invalid, err
	}

	// Risk: Low - Medium
	// POST request to /user/keys
	// Payload is invalid, so it shouldn't actually post.
	_, resp, err = client.Users.CreateKey(context.Background(), &gh.Key{})
	if resp == nil {
		return Invalid, err
	}
	switch resp.StatusCode {
	case 403:
		return GitKeysRead, nil
	case 422:
		return GitKeysWrite, nil
	case 200, 201, 204:
		log.Fatal("This should never happen. We are creating a key with an invalid payload.")
		return GitKeysWrite, nil
	default:
		return Invalid, err
	}
}

func getLimitsPermission(client *gh.Client, user *gh.User) (Permission, error) {
	// Risk: Extremely Low
	// GET request to /user/interaction-limits
	req, err := client.NewRequest("GET", "https://api.github.com/user/interaction-limits", nil)
	if err != nil {
		return Invalid, err
	}
	resp, err := client.Do(context.Background(), req, nil)
	if resp == nil {
		return Invalid, err
	}
	switch resp.StatusCode {
	case 403:
		return NoAccess, nil
	case 200, 204:
		break
	default:
		return Invalid, err
	}

	// Risk: Low
	// PUT request to /user/interaction-limits
	// Payload is invalid, so it shouldn't actually post.
	req, err = client.NewRequest("PUT", "https://api.github.com/user/interaction-limits", nil)
	if err != nil {
		return Invalid, err
	}
	resp, err = client.Do(context.Background(), req, nil)
	if resp == nil {
		return Invalid, err
	}
	switch resp.StatusCode {
	case 403:
		return LimitsRead, nil
	case 422:
		return LimitsWrite, nil
	case 200, 204:
		log.Fatal("This should never happen. We are setting interaction limits with an invalid payload.")
		return LimitsWrite, nil
	default:
		return Invalid, err
	}
}

func getPlanPermission(client *gh.Client, user *gh.User) (Permission, error) {
	// Risk: Extremely Low
	// GET request to /user/{username}/settings/billing/actions
	_, resp, err := client.Billing.GetActionsBillingUser(context.Background(), *user.Login)
	if resp == nil {
		return Invalid, err
	}
	switch resp.StatusCode {
	case 403, 404:
		return NoAccess, nil
	case 200:
		return PlanRead, nil
	default:
		return Invalid, err
	}
}

func getProfilePermission(client *gh.Client, user *gh.User) (Permission, error) {
	// Risk: Low
	// POST request to /user/social_accounts
	// Payload is invalid, so it shouldn't actually patch.
	req, err := client.NewRequest("POST", "https://api.github.com/user/social_accounts", nil)
	if err != nil {
		return Invalid, err
	}
	resp, err := client.Do(context.Background(), req, nil)
	if resp == nil {
		return Invalid, err
	}
	switch resp.StatusCode {
	case 403, 404:
		return NoAccess, nil
	case 422:
		return ProfileWrite, nil
	case 200, 201, 204:
		log.Fatal("This should never happen. We are creating a social account with an invalid payload.")
		return ProfileWrite, nil
	default:
		return Invalid, err
	}
}

func getSigningKeysPermission(client *gh.Client, user *gh.User) (Permission, error) {
	// Risk: Extremely Low
	// GET request to /user/ssh_signing_keys
	_, resp, err := client.Users.ListSSHSigningKeys(context.Background(), "", nil)
	if resp == nil {
		return Invalid, err
	}
	switch resp.StatusCode {
	case 403, 404:
		return NoAccess, nil
	case 200:
		break
	default:
		return Invalid, err
	}

	// Risk: Low - Medium
	// POST request to /user/ssh_signing_keys
	// Payload is invalid, so it shouldn't actually post.
	_, resp, err = client.Users.CreateSSHSigningKey(context.Background(), &gh.Key{})
	if resp == nil {
		return Invalid, err
	}
	switch resp.StatusCode {
	case 403:
		return SigningKeysRead, nil
	case 422:
		return SigningKeysWrite, nil
	case 200, 201, 204:
		log.Fatal("This should never happen. We are creating a SSH key with an invalid payload.")
		return SigningKeysWrite, nil
	default:
		return Invalid, err
	}
}

func getStarringPermission(client *gh.Client, user *gh.User) (Permission, error) {
	// Note: We can't test READ_WRITE b/c Unstar() isn't working even with READ_WRITE permissions.
	// Note: GET /user/starred returns the same results regardless of permissions
	//       but since all have the same access, we'll call it READ_ONLY for now.
	return StarringRead, nil
}

func getWatchingPermission(client *gh.Client, user *gh.User) (Permission, error) {
	// Note: GET /user/subscriptions returns the same results regardless of permissions
	//       but since all have the same access, we'll call it READ_ONLY for now.
	return WatchingRead, nil
}

func analyzeUserPermissions(client *gh.Client, user *gh.User) ([]Permission, error) {
	perms := []Permission{}
	for _, permFunc := range acctPermFuncMap {
		access, err := permFunc(client, user)
		if err != nil {
			// TODO: Log error.
			continue
		}
		perms = append(perms, access)
	}

	return perms, nil
}

func AnalyzeFineGrainedToken(client *gh.Client, meta *common.TokenMetadata, shallowCheck bool) (*common.SecretInfo, error) {
	allRepos, err := common.GetAllReposForUser(client)
	if err != nil {
		return nil, err
	}

	allGists, err := common.GetAllGistsForUser(client)
	if err != nil {
		return nil, err
	}
	accessibleRepos := make([]*gh.Repository, 0)
	for _, repo := range allRepos {
		perm, err := getMetadataPermission(client, repo, Invalid)
		if err != nil {
			// TODO: Log error.
			continue
		}
		if perm != Invalid {
			accessibleRepos = append(accessibleRepos, repo)
		}
	}

	repoAccessMap := []Permission{}
	userAccessMap := []Permission{}

	if !shallowCheck {
		// Check our access
		perms, err := analyzeRepositoryPermissions(client, accessibleRepos)
		if err != nil {
			return nil, err
		}
		for _, perm := range perms {
			if perm != Invalid && perm != NoAccess {
				repoAccessMap = append(repoAccessMap, perm)
			}
		}

		perms, err = analyzeUserPermissions(client, meta.User)
		if err != nil {
			return nil, err
		}
		for _, perm := range perms {
			if perm != Invalid && perm != NoAccess {
				userAccessMap = append(userAccessMap, perm)
			}
		}
	}

	return &common.SecretInfo{
		Metadata:        meta,
		Repos:           allRepos,
		Gists:           allGists,
		AccessibleRepos: accessibleRepos,
		RepoAccessMap:   repoAccessMap,
		UserAccessMap:   userAccessMap,
	}, nil
}

func PrintFineGrainedToken(cfg *config.Config, info *common.SecretInfo) {
	if len(info.AccessibleRepos) == 0 {
		// If no repos are accessible, then we only have read access to public repos
		color.Red("[!] Repository Access: Public Repositories (read-only)\n")
	} else {
		// Print out the repos the token can access
		color.Green(fmt.Sprintf("Found %v", len(info.AccessibleRepos)) + " Accessible Repositor(ies) \n")
		common.PrintGitHubRepos(info.AccessibleRepos)

		// Print out the access map
		perms, ok := info.RepoAccessMap.([]Permission)
		if !ok {
			panic("Repo Access Map is not of type Permission")
		}
		printFineGrainedPermissions(perms, cfg.ShowAll, true)
	}

	perms, ok := info.UserAccessMap.([]Permission)
	if !ok {
		panic("Repo Access Map is not of type Permission")
	}

	printFineGrainedPermissions(perms, cfg.ShowAll, false)
	common.PrintGists(info.Gists, cfg.ShowAll)
}

func printFineGrainedPermissions(accessMap []Permission, showAll bool, repoPermissions bool) {
	permissionCount := 0
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Permission Type", "Permission" /* Add more column headers if needed */})

	for _, perm := range accessMap {
		permStr, _ := perm.ToString()
		if perm == Invalid {
			// don't change permissionCount
		} else {
			permissionCount++
		}
		if !showAll && perm == Invalid {
			continue
		} else {
			k, v := permissionFormatter(permStr, perm)
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
