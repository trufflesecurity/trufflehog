package github

import (
	"fmt"
	"net/url"
	"strings"
)

func wikiCloneURLForRepo(repoURL string) (string, bool) {
	if !strings.HasSuffix(repoURL, ".git") || strings.HasSuffix(repoURL, ".wiki.git") {
		return "", false
	}
	return strings.TrimSuffix(repoURL, ".git") + ".wiki.git", true
}

func repoCloneURLForWikiCloneURL(repoURL string) string {
	// Installation APIs return repository clone URLs, so map wiki clone URLs
	// back to their owning repository before comparing installation ownership.
	if strings.HasSuffix(repoURL, ".wiki.git") {
		return strings.TrimSuffix(repoURL, ".wiki.git") + ".git"
	}
	return repoURL
}

func wikiWebURLForRepoInfo(endpoint string, info repoInfo) string {
	return (&url.URL{
		Scheme: "https",
		Host:   githubWebHost(endpoint),
	}).JoinPath(info.owner, info.name, "wiki").String()
}

func wikiWebURLForRepoCloneURL(repoURL string) (string, error) {
	u, err := url.Parse(repoURL)
	if err != nil {
		return "", fmt.Errorf("could not parse repo URL %q: %w", repoURL, err)
	}
	u.Path = strings.TrimSuffix(strings.TrimRight(u.Path, "/"), ".git")
	return u.JoinPath("wiki").String(), nil
}

func canonicalAPIEndpoint(endpoint string) string {
	if isGitHubCloudEndpoint(endpoint) {
		return cloudV3Endpoint
	}
	if !hasURLScheme(endpoint) {
		return "https://" + strings.TrimLeft(endpoint, "/")
	}
	return endpoint
}

func hasURLScheme(rawURL string) bool {
	if !strings.Contains(rawURL, "://") {
		return false
	}
	u, err := url.Parse(rawURL)
	return err == nil && u.IsAbs() && u.Scheme != ""
}

func isSCPStyleRepoURL(repoURL string) bool {
	return !hasURLScheme(repoURL) && strings.Contains(repoURL, "@") && strings.Contains(repoURL, ":")
}

func isGitHubCloudEndpoint(endpoint string) bool {
	host, ok := endpointHost(endpoint)
	if !ok {
		return endpoint == ""
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if strings.HasPrefix(host, "[") {
		// IPv6 endpoints are always Enterprise hosts.
		return false
	}
	if hostWithoutPort, _, ok := strings.Cut(host, ":"); ok {
		host = hostWithoutPort
	}
	return host == "github.com" || strings.HasSuffix(host, ".github.com")
}

func endpointHost(endpoint string) (string, bool) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return "", false
	}

	u, err := url.Parse(endpoint)
	if err == nil && u.Host != "" {
		return u.Host, true
	}

	if strings.Contains(endpoint, "://") {
		return "", false
	}
	host, _, _ := strings.Cut(strings.Trim(endpoint, "/"), "/")
	return host, host != ""
}

func endpointBaseURL(endpoint string) (*url.URL, error) {
	host, ok := endpointHost(endpoint)
	if !ok {
		return nil, fmt.Errorf("invalid endpoint: %q", endpoint)
	}

	scheme := "https"
	if u, err := url.Parse(endpoint); err == nil && u.Scheme != "" {
		scheme = u.Scheme
	}
	return &url.URL{Scheme: scheme, Host: host}, nil
}

func githubWebHost(endpoint string) string {
	if isGitHubCloudEndpoint(endpoint) {
		return "github.com"
	}
	host, ok := endpointHost(endpoint)
	if !ok {
		return "github.com"
	}
	return host
}
