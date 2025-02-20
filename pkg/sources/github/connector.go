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

type Connector interface {
	// APIClient returns a configured GitHub client that can be used for GitHub API operations.
	APIClient() *github.Client
	// Clone clones a repository using the configured authentication information.
	Clone(ctx context.Context, repoURL string) (string, *gogit.Repository, error)
}

func NewConnector(
	cred any,
	apiEndpoint string,
	handleRateLimit func(ctx context.Context, errIn error, reporters ...errorReporter) bool,
) (Connector, error) {

	switch cred := cred.(type) {
	case *credentialspb.GitHubApp:
		log.RedactGlobally(cred.GetPrivateKey())
		return newAppConnector(apiEndpoint, cred)
	case *credentialspb.BasicAuth:
		log.RedactGlobally(cred.GetPassword())
		return newBasicAuthConnector(apiEndpoint, cred)
	case string: // Token
		log.RedactGlobally(cred)
		return newTokenConnector(apiEndpoint, cred, handleRateLimit)
	case *credentialspb.Unauthenticated:
		return newUnauthenticatedConnector(apiEndpoint)
	default:
		return nil, fmt.Errorf("unknown credential type %T", cred)
	}
}
