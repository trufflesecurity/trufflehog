package github

import (
	"fmt"

	gogit "github.com/go-git/go-git/v5"
	"github.com/google/go-github/v67/github"
	"github.com/trufflesecurity/trufflehog/v3/pkg/log"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/credentialspb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
)

const cloudEndpoint = "https://api.github.com"

type Connector interface {
	// APIClient returns a configured GitHub client that can be used for GitHub API operations.
	APIClient() *github.Client
	// Clone clones a repository using the configured authentication information.
	Clone(ctx context.Context, repoURL string) (string, *gogit.Repository, error)
}

type Token string

type Credential interface {
	*credentialspb.GitHubApp | *credentialspb.BasicAuth | Token | *credentialspb.Unauthenticated
}

func NewConnector[C Credential](
	credential C,
	apiEndpoint string,
	handleRateLimit func(ctx context.Context, errIn error, reporters ...errorReporter) bool,
) (Connector, error) {
	switch cred := any(credential).(type) {
	case *credentialspb.GitHubApp:
		log.RedactGlobally(cred.GetPrivateKey())
		return newAppConnector(apiEndpoint, cred)
	case *credentialspb.BasicAuth:
		log.RedactGlobally(cred.Password)
		return newBasicAuthConnector(apiEndpoint, cred)
	case Token:
		log.RedactGlobally(string(cred))
		return newTokenConnector(apiEndpoint, string(cred), handleRateLimit)
	case *credentialspb.Unauthenticated:
		return newUnauthenticatedConnector(apiEndpoint)
	default:
		return nil, fmt.Errorf("unknown authentication type %T", credential)
	}
}

func newConnectorFromSource(source *Source) (Connector, error) {
	apiEndpoint := source.conn.Endpoint
	if apiEndpoint == "" || endsWithGithub.MatchString(apiEndpoint) {
		apiEndpoint = cloudEndpoint
	}

	switch cred := source.conn.GetCredential().(type) {
	case *sourcespb.GitHub_GithubApp:
		return NewConnector(cred.GithubApp, apiEndpoint, source.handleRateLimit)
	case *sourcespb.GitHub_BasicAuth:
		return NewConnector(cred.BasicAuth, apiEndpoint, source.handleRateLimit)
	case *sourcespb.GitHub_Token:
		return NewConnector(Token(cred.Token), apiEndpoint, source.handleRateLimit)
	case *sourcespb.GitHub_Unauthenticated:
		return NewConnector(cred.Unauthenticated, apiEndpoint, source.handleRateLimit)
	default:
		return nil, fmt.Errorf("unknown authentication type %T", source.conn.GetCredential())
	}
}
