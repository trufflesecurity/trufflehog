package giturl

import (
	"net/url"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

type provider string

const (
	providerGithub    provider = "Github"
	providerGitlab    provider = "Gitlab"
	providerBitbucket provider = "Bitbucket"
	providerAzure     provider = "Azure"

	urlGithub    = "github.com/"
	urlGitlab    = "gitlab.com/"
	urlBitbucket = "bitbucket.org/"
	urlAzure     = "dev.azure.com/"
)

func determineProvider(repo string) provider {
	switch {
	case strings.Contains(repo, urlGithub):
		return providerGithub
	case strings.Contains(repo, urlGitlab):
		return providerGitlab
	case strings.Contains(repo, urlBitbucket):
		return providerBitbucket
	case strings.Contains(repo, urlAzure):
		return providerAzure
	default:
		return ""
	}
}

func NormalizeBitbucketRepo(repoURL string) (string, error) {
	if !strings.HasPrefix(repoURL, "https") {
		return "", errors.New("Bitbucket requires https repo urls: e.g. https://bitbucket.org/org/repo.git")
	}

	return NormalizeOrgRepoURL(providerBitbucket, repoURL)
}

func NormalizeGerritProject(project string) (string, error) {
	return "", errors.Errorf("Not yet implemented")
}

func NormalizeGithubRepo(repoURL string) (string, error) {
	return NormalizeOrgRepoURL(providerGithub, repoURL)
}

func NormalizeGitlabRepo(repoURL string) (string, error) {
	if !strings.HasPrefix(repoURL, "http:") && !strings.HasPrefix(repoURL, "https:") {
		return "", errors.New("Gitlab requires http/https repo urls: e.g. https://gitlab.com/org/repo.git")
	}

	return NormalizeOrgRepoURL(providerGitlab, repoURL)
}

// NormalizeOrgRepoURL attempts to normalize repos for any provider using the example.com/org/repo style.
// e.g. %s, Gitlab and Bitbucket
func NormalizeOrgRepoURL(provider provider, repoURL string) (string, error) {
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

// GenerateLink crafts a link to the specific file from a commit.
// Supports GitHub, GitLab, Bitbucket, and Azure Repos.
// If the provider supports hyperlinks to specific lines, the line number will be included.
func GenerateLink(repo, commit, file string, line int64) string {
	switch determineProvider(repo) {
	case providerBitbucket:
		return repo[:len(repo)-4] + "/commits/" + commit

	case providerGithub, providerGitlab:
		var baseLink string
		if file == "" {
			baseLink = repo[:len(repo)-4] + "/commit/" + commit
		} else {
			baseLink = repo[:len(repo)-4] + "/blob/" + commit + "/" + file
			if line > 0 {
				baseLink += "#L" + strconv.FormatInt(line, 10)
			}
		}
		return baseLink

	case providerAzure:
		baseLink := repo + "?path=" + file + "&version=GB" + commit
		if line > 0 {
			baseLink += "&line=" + strconv.FormatInt(line, 10)
		}
		return baseLink

	default:
		return ""
	}
}
