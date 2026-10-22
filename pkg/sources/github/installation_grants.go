package github

import "github.com/google/go-github/v67/github"

// Permissions the comment listings need, in the form permissionError names
// them.
var (
	issuesRead       = permission{name: "issues", access: "read"}
	pullRequestsRead = permission{name: "pull_requests", access: "read"}
)

// installationGrants is what a GitHub App installation grants, for the
// permissions the comment scan needs. A nil *installationGrants means the
// grants aren't known (a personal access token, or an App token whose
// permissions couldn't be read), and every listing runs as if granted; a 403
// is then classified from its response by asPermissionError.
//
// The grants matter beyond outright refusals because GitHub doesn't refuse
// every listing they only partly cover. Measured against a live installation:
//   - /issues with Issues (read) but not Pull requests (read) returns the
//     issues and leaves out the pull requests.
//   - /issues/comments with only one of the two returns only the comments that
//     one covers: issue comments with Issues (read), pull request
//     conversation comments with Pull requests (read).
//
// Both answer 200 with no error, so the comment scan reads the grants to skip
// listings that can't succeed and to report what the others leave out (see
// processIssueandPRsWithCommentsREST).
type installationGrants struct {
	installationID int64
	issues         bool
	pullRequests   bool
}

// newInstallationGrants reads the comment-relevant grants from an access
// token's permissions. GitHub lists them on every installation token, so a
// token without any is unexpected; it returns nil (unknown) rather than
// treating the installation as granting nothing.
func newInstallationGrants(installationID int64, perms *github.InstallationPermissions) *installationGrants {
	if perms == nil {
		return nil
	}
	return &installationGrants{
		installationID: installationID,
		issues:         grantsRead(perms.GetIssues()),
		pullRequests:   grantsRead(perms.GetPullRequests()),
	}
}

// grantsRead reports whether an installation permission level allows
// reading. Write access includes read.
func grantsRead(level string) bool {
	switch level {
	case "read", "write", "admin":
		return true
	default:
		return false
	}
}

// issuesGranted and pullRequestsGranted report whether the permission is
// granted, treating unknown grants as granted so listings run as they would
// without the precheck.
func (g *installationGrants) issuesGranted() bool       { return g == nil || g.issues }
func (g *installationGrants) pullRequestsGranted() bool { return g == nil || g.pullRequests }
