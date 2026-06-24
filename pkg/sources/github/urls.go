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

func wikiCloneURLForRepoInfo(repoURL string, info repoInfo) (string, bool) {
	return wikiCloneURLForRepoName(repoURL, info.name)
}

func wikiCloneURLForRepoName(repoURL, name string) (string, bool) {
	_, parts, err := getRepoURLParts(repoURL)
	if err != nil || len(parts) != 3 || !strings.EqualFold(parts[2], name) || !strings.HasSuffix(repoURL, ".git") {
		return "", false
	}
	return strings.TrimSuffix(repoURL, ".git") + ".wiki.git", true
}

func repoCloneURLForWikiCloneURL(repoURL string) (string, bool) {
	if strings.HasSuffix(repoURL, ".wiki.git") {
		return strings.TrimSuffix(repoURL, ".wiki.git") + ".git", true
	}
	return "", false
}

func repoURLsForInstallationLookup(repoURL string) []string {
	repoURLs := []string{repoURL}
	// Installation APIs return repository clone URLs, not wiki clone URLs. Keep
	// the exact URL first so real repositories named "*.wiki" win before the
	// wiki-parent fallback is attempted.
	if parentRepoURL, ok := repoCloneURLForWikiCloneURL(repoURL); ok {
		repoURLs = append(repoURLs, parentRepoURL)
	}
	return repoURLs
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
	if hostWithoutPort, port, ok := strings.Cut(host, ":"); ok {
		host = hostWithoutPort
		if port != "" && port != "443" {
			return false
		}
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
	if hasURLScheme(endpoint) {
		u, err := url.Parse(endpoint)
		if err != nil {
			return nil, fmt.Errorf("invalid endpoint: %q", endpoint)
		}
		scheme = u.Scheme
	}
	return &url.URL{Scheme: scheme, Host: host}, nil
}

func repoCloneURLForTargetEndpoint(endpoint, repoURL string) (string, error) {
	u, err := url.Parse(repoURL)
	if err != nil {
		return "", fmt.Errorf("could not parse target repository URL %q: %w", repoURL, err)
	}
	if u.Host == "" {
		return "", fmt.Errorf("target repository URL %q has no host", repoURL)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("target repository URL %q has unsupported scheme %q", repoURL, u.Scheme)
	}

	endpointScheme := "https"
	if hasURLScheme(endpoint) {
		endpointURL, err := url.Parse(endpoint)
		if err != nil {
			return "", fmt.Errorf("invalid endpoint: %q", endpoint)
		}
		if endpointURL.Scheme != "http" && endpointURL.Scheme != "https" {
			return "", fmt.Errorf("endpoint %q has unsupported scheme %q", endpoint, endpointURL.Scheme)
		}
		endpointScheme = endpointURL.Scheme
	}

	expectedHost := stripDefaultPort(githubWebHost(endpoint), endpointScheme)
	actualHost := stripDefaultPort(u.Host, u.Scheme)
	if !strings.EqualFold(actualHost, expectedHost) {
		return "", fmt.Errorf("target repository host %q does not match GitHub endpoint host %q", u.Host, expectedHost)
	}

	u.Scheme = endpointScheme
	return u.String(), nil
}

func stripDefaultPort(host, scheme string) string {
	if strings.HasPrefix(host, "[") {
		return host
	}
	hostWithoutPort, port, ok := strings.Cut(host, ":")
	if !ok {
		return host
	}
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		return hostWithoutPort
	}
	return host
}

func isWikiLink(link string) bool {
	u, err := url.Parse(link)
	if err != nil {
		return false
	}
	segments := strings.Split(strings.Trim(u.Path, "/"), "/")
	return len(segments) >= 3 && segments[2] == "wiki"
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
