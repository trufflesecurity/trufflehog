package github

import (
	"fmt"
	"net/url"
	"strings"
)

// safeRepoURL removes any username or password from a repo URL so it can be
// logged.
func safeRepoURL(repo string) string {
	// a normal URL like "https://user:pass@host/org/repo": let url.Parse find
	// the user info and drop it
	u, err := url.Parse(repo)
	if err == nil && u.Host != "" {
		u.User = nil
		return u.String()
	}

	// anything else is a repo name like "org/repo", or a URL that url.Parse
	// rejects, so drop the user info by hand
	if prefix, _, rest, found := splitUserInfo(repo); found {
		return prefix + rest
	}
	return repo
}

// splitUserInfo splits a repo that url.Parse rejects, like an SCP-style URL
// "user:pass@host:org/repo" or a mix like "https://token@host:org/repo", into
// the scheme prefix ("https://" or ""), the user info and the rest. The user
// info always sits before an "@" in the part before the first "/" after any
// scheme. found is false when there is no such "@".
func splitUserInfo(repo string) (prefix, userInfo, rest string, found bool) {
	scheme, afterScheme, hasScheme := strings.Cut(repo, "://")
	if hasScheme {
		prefix = scheme + "://"
	} else {
		afterScheme = repo
	}
	hostPart, _, _ := strings.Cut(afterScheme, "/")
	at := strings.LastIndex(hostPart, "@")
	if at < 0 {
		return prefix, "", afterScheme, false
	}
	return prefix, afterScheme[:at], afterScheme[at+1:], true
}

// repoCredential returns the secret in a repo URL's user info, or "" if it has
// none, so it can be redacted from logs. That is the password, or for an
// http(s) URL with no password the username, since "https://TOKEN@host" puts
// the token there. Other usernames are not secret, and redacting one like
// "git" would hide that word in every log line.
func repoCredential(repo string) string {
	var prefix, username, password string
	if u, err := url.Parse(repo); err == nil && u.Host != "" {
		if u.User == nil {
			return ""
		}
		prefix = u.Scheme + "://"
		username = u.User.Username()
		password, _ = u.User.Password()
	} else {
		var userInfo string
		var found bool
		prefix, userInfo, _, found = splitUserInfo(repo)
		if !found {
			return ""
		}
		username, password, _ = strings.Cut(userInfo, ":")
	}

	// a password can be present but empty, as in "https://TOKEN:@host"
	if password != "" {
		return password
	}
	if prefix == "http://" || prefix == "https://" {
		return username
	}
	return ""
}

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
