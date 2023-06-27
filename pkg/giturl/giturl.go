package giturl

import (
	"net/url"
	"strings"

	"github.com/pkg/errors"
)

func NormalizeBitbucketRepo(repoURL string) (string, error) {
	if !strings.HasPrefix(repoURL, "https") {
		return "", errors.New("Bitbucket requires https repo urls: e.g. https://bitbucket.org/org/repo.git")
	}

	return NormalizeOrgRepoURL("Bitbucket", repoURL)
}

func NormalizeGerritProject(project string) (string, error) {
	return "", errors.Errorf("Not yet implemented")
}

func NormalizeGithubRepo(repoURL string) (string, error) {
	return NormalizeOrgRepoURL("Github", repoURL)
}

func NormalizeGitlabRepo(repoURL string) (string, error) {
	if !strings.HasPrefix(repoURL, "http:") && !strings.HasPrefix(repoURL, "https:") {
		return "", errors.New("Gitlab requires http/https repo urls: e.g. https://gitlab.com/org/repo.git")
	}

	return NormalizeOrgRepoURL("Gitlab", repoURL)
}

// NormalizeOrgRepoURL attempts to normalize repos for any provider using the example.com/org/repo style.
// e.g. %s, Gitlab and Bitbucket
func NormalizeOrgRepoURL(provider, repoURL string) (string, error) {
	if strings.HasSuffix(repoURL, ".git") {
		return repoURL, nil
	}

	parsed, err := url.Parse(repoURL)
	if err != nil {
		return "", errors.Wrapf(err, "Unable to parse %s Repo URL", provider)
	}

	// The provider repo url should have a path length of 3
	//               0 / 1 / 2     (3 total)
	// e.g. example.com/org/repo
	// If it is 1, or the 2nd section is empty, it's likely just the org.
	// If it is 3, there's something at the end that shouldn't be there.
	// Let the user know in any case.
	switch parts := strings.Split(parsed.Path, "/"); {
	case len(parts) <= 1:
		return "", errors.Errorf("%s repo appears to be missing the path. Repo url: %q", provider, repoURL)

	case len(parts) == 2:
		org := parts[1]

		if len(org) == 0 {
			return "", errors.Errorf("%s repo appears to be missing the org name. Repo url: %q", provider, repoURL)
		} else {
			return "", errors.Errorf("%s repo appears to be missing the repo name. Org: %q Repo url: %q", provider, org, repoURL)
		}

	case len(parts) == 3:
		org, repo := parts[1], parts[2]

		if len(org) == 0 {
			return "", errors.Errorf("%s repo appears to be missing the org name. Repo url: %q", provider, repoURL)
		}
		if len(repo) == 0 {
			return "", errors.Errorf("%s repo appears to be missing the repo name. Org: %q Repo url: %q", provider, org, repoURL)
		}

	case len(parts) > 3 && strings.HasSuffix(parsed.Path, "/"):
		return "", errors.Errorf("%s repo contains a trailing slash. Repo url: %q", provider, repoURL)
	}

	// If we're here it's probably a provider repo without ".git" at the end, so add it and return
	parsed.Path += ".git"
	return parsed.String(), nil
}
