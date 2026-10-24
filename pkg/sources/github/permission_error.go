package github

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/go-github/v67/github"
)

// acceptedPermissionsHeader is the response header in which GitHub names what
// an endpoint requires. GitHub refuses a request the credential isn't
// permitted to make with a 403 ("Resource not accessible by integration" for
// GitHub App tokens, "...by personal access token" for fine-grained tokens)
// that carries this header. The raw error doesn't say which permission is
// missing, so comment walks rewrite these 403s into a permissionError that
// does. The header's value is a comma-separated list of permissions that are
// all required; a semicolon separates alternative lists, any one of which is
// enough. See
// https://docs.github.com/en/rest/using-the-rest-api/troubleshooting-the-rest-api#resource-not-accessible
const acceptedPermissionsHeader = "X-Accepted-GitHub-Permissions"

// permission is one entry of the header, such as issues=read.
type permission struct {
	name   string
	access string
}

// String renders the permission the way GitHub's settings pages label it, for
// example "Pull requests (read)".
func (p permission) String() string {
	label := strings.ReplaceAll(p.name, "_", " ")
	return fmt.Sprintf("%s%s (%s)", strings.ToUpper(label[:1]), label[1:], p.access)
}

// credentialKind is the kind of credential GitHub says it refused, read from
// the 403's message. The fix differs: an app's permissions are changed by its
// owner and then accepted on each installation, while a fine-grained token's
// are changed on the token.
type credentialKind int

const (
	credentialUnknown credentialKind = iota
	credentialApp
	credentialFineGrainedToken
)

// permissionError reports comment-scan coverage lost because the credential
// lacks a permission. accepted holds the permission sets that would restore
// it: any one set is enough, and a set needs every permission in it.
//
// Most come from a request GitHub refused, built by asPermissionError: method
// and path identify the request, and message is GitHub's own error text, kept
// so the error still reads like the 403 it replaces.
//
// The rest come from a GitHub App installation's grants, read before any
// request (see installationGrants): installationID names the installation,
// and outcome says what the scan did about the missing permission. These
// have no request and wrap no error.
type permissionError struct {
	accepted   [][]permission
	credential credentialKind
	method     string
	path       string
	message    string
	err        error

	installationID int64
	outcome        string
}

// newSkippedListingError reports a listing the scan skipped without calling
// GitHub, because the installation grants none of the permission sets that
// would let it succeed.
func newSkippedListingError(installationID int64, accepted ...[]permission) *permissionError {
	return &permissionError{
		accepted:       accepted,
		credential:     credentialApp,
		installationID: installationID,
		outcome:        "the listing was skipped",
	}
}

// newNarrowedListingError reports items GitHub leaves out of a listing
// because the installation doesn't grant the permission that covers them.
// The listing itself succeeds and returns everything else, with nothing in
// the response to say items are missing, so this error is the only record of
// the gap.
func newNarrowedListingError(installationID int64, listing string, accepted ...[]permission) *permissionError {
	return &permissionError{
		accepted:       accepted,
		credential:     credentialApp,
		installationID: installationID,
		outcome:        "GitHub left them out of the " + listing + " listing",
	}
}

func (e *permissionError) Error() string {
	var subject, fix string
	switch e.credential {
	case credentialApp:
		subject = "missing GitHub App permission"
		fix = "update the app's permissions and accept the change on the installation"
	case credentialFineGrainedToken:
		subject = "missing personal access token permission"
		fix = "update the token's permissions"
	default:
		subject = "missing GitHub permission"
		fix = "update the credential's permissions"
	}

	if e.outcome != "" {
		verb := "is"
		if len(e.accepted) == 1 && len(e.accepted[0]) > 1 {
			verb = "are"
		}
		return fmt.Sprintf("%s: %s %s needed; %s (not granted to installation %d, so %s)",
			subject, describeAccepted(e.accepted), verb, fix, e.installationID, e.outcome)
	}

	request := "request"
	if e.path != "" {
		request = e.method + " " + e.path
	}
	return fmt.Sprintf("%s: the request needs %s; %s (%s returned 403 %s)",
		subject, describeAccepted(e.accepted), fix, request, e.message)
}

func (e *permissionError) Unwrap() error { return e.err }

// asPermissionError returns err as a *permissionError when it is a 403 that
// names the permissions it wanted, and returns err unchanged otherwise. 403s
// without the header pass through as they are: rate limits arrive as their own
// error types, and SAML enforcement, IP allow lists, and GitHub Enterprise
// Server versions that don't send the header leave nothing to name.
func asPermissionError(err error) error {
	var errResp *github.ErrorResponse
	if !errors.As(err, &errResp) || errResp.Response == nil || errResp.Response.StatusCode != http.StatusForbidden {
		return err
	}
	accepted := parseAcceptedPermissions(errResp.Response.Header.Get(acceptedPermissionsHeader))
	if len(accepted) == 0 {
		return err
	}

	permErr := &permissionError{
		accepted:   accepted,
		credential: credentialFromMessage(errResp.Message),
		message:    errResp.Message,
		err:        err,
	}
	if req := errResp.Response.Request; req != nil && req.URL != nil {
		permErr.method = req.Method
		permErr.path = req.URL.Path
	}
	return permErr
}

// parseAcceptedPermissions parses an acceptedPermissionsHeader value into its
// alternative permission sets. A value that doesn't parse cleanly returns
// nil, so a format change on GitHub's side leaves the original 403 intact
// rather than producing a message that names the wrong permissions.
func parseAcceptedPermissions(header string) [][]permission {
	if strings.TrimSpace(header) == "" {
		return nil
	}
	var sets [][]permission
	for _, rawSet := range strings.Split(header, ";") {
		var set []permission
		for _, entry := range strings.Split(rawSet, ",") {
			name, access, ok := strings.Cut(entry, "=")
			name, access = strings.TrimSpace(name), strings.TrimSpace(access)
			if !ok || name == "" || access == "" {
				return nil
			}
			set = append(set, permission{name: name, access: access})
		}
		sets = append(sets, set)
	}
	return sets
}

// describeAccepted renders the accepted permission sets as a phrase:
// "Issues (read)", "Pull requests (write) and Contents (read)", "Issues (read)
// or Pull requests (read)", or, when an alternative needs more than one
// permission, "either A (read) and B (read), or C (read) and B (read)".
func describeAccepted(sets [][]permission) string {
	described := make([]string, len(sets))
	compound := false
	for i, set := range sets {
		names := make([]string, len(set))
		for j, p := range set {
			names[j] = p.String()
		}
		described[i] = strings.Join(names, " and ")
		compound = compound || len(set) > 1
	}
	switch {
	case len(described) == 1:
		return described[0]
	case compound:
		return "either " + strings.Join(described, ", or ")
	default:
		return strings.Join(described, " or ")
	}
}

// credentialFromMessage reads which kind of credential GitHub refused from the
// 403's message.
func credentialFromMessage(message string) credentialKind {
	lower := strings.ToLower(message)
	switch {
	case strings.Contains(lower, "by integration"):
		return credentialApp
	case strings.Contains(lower, "by personal access token"):
		return credentialFineGrainedToken
	default:
		return credentialUnknown
	}
}
