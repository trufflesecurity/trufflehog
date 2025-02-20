package github

import (
	"fmt"

	gogit "github.com/go-git/go-git/v5"
	"github.com/google/go-github/v67/github"
	"github.com/trufflesecurity/trufflehog/v3/pkg/log"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/credentialspb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

const cloudEndpoint = "https://api.github.com"

// Connector abstracts over the authenticated ways that TruffleHog can interact with GitHub: cloning and using the API.
type Connector interface {
	// APIClient returns a configured GitHub client that can be used for GitHub API operations.
	APIClient() *github.Client
	// Clone clones a repository using the configured authentication information.
	Clone(ctx context.Context, repoURL string) (string, *gogit.Repository, error)
}

type Token string

// Credential is an interface used to constrain the generic creation of Connector objects.
type Credential interface {
	*credentialspb.GitHubApp | *credentialspb.BasicAuth | Token | *credentialspb.Unauthenticated
}

// NewConnector creates a new Connector using the provided credential, API endpoint, and rate limit handler. The type
// of connector is determined from the type of the provided credential.
func NewConnector[C Credential](
	cred C,
	apiEndpoint string,
	handleRateLimit func(ctx context.Context, errIn error, reporters ...errorReporter) bool,
) (Connector, error) {

	switch cred := any(cred).(type) {
	case *credentialspb.GitHubApp:
		log.RedactGlobally(cred.GetPrivateKey())
		return newAppConnector(apiEndpoint, cred)
	case *credentialspb.BasicAuth:
		log.RedactGlobally(cred.GetPassword())
		return newBasicAuthConnector(apiEndpoint, cred)
	case Token:
		log.RedactGlobally(string(cred))
		return newTokenConnector(apiEndpoint, string(cred), handleRateLimit)
	case *credentialspb.Unauthenticated:
		return newUnauthenticatedConnector(apiEndpoint)
	default:
		return nil, fmt.Errorf("unknown credential type %T", cred)
	}
}
