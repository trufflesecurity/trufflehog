package github

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWikiCloneURLForRepo(t *testing.T) {
	got, ok := wikiCloneURLForRepo("https://github.com/owner/repo.git")
	require.True(t, ok)
	assert.Equal(t, "https://github.com/owner/repo.wiki.git", got)

	_, ok = wikiCloneURLForRepo("https://github.com/owner/repo.wiki.git")
	assert.False(t, ok)

	_, ok = wikiCloneURLForRepo("https://github.com/owner/repo")
	assert.False(t, ok)
}

func TestRepoCloneURLForWikiCloneURL(t *testing.T) {
	got, ok := repoCloneURLForWikiCloneURL("https://github.com/owner/repo.wiki.git")
	require.True(t, ok)
	assert.Equal(t, "https://github.com/owner/repo.git", got)

	_, ok = repoCloneURLForWikiCloneURL("https://github.com/owner/repo.git")
	assert.False(t, ok)
}

func TestRepoURLsForInstallationLookup(t *testing.T) {
	assert.Equal(
		t,
		[]string{"https://github.com/owner/repo.git"},
		repoURLsForInstallationLookup("https://github.com/owner/repo.git"),
	)
	assert.Equal(
		t,
		[]string{"https://github.com/owner/repo.wiki.git", "https://github.com/owner/repo.git"},
		repoURLsForInstallationLookup("https://github.com/owner/repo.wiki.git"),
	)
}

func TestWikiCloneURLForRepoInfo(t *testing.T) {
	got, ok := wikiCloneURLForRepoInfo("https://github.com/owner/repo.wiki.git", repoInfo{name: "repo.wiki"})
	require.True(t, ok)
	assert.Equal(t, "https://github.com/owner/repo.wiki.wiki.git", got)

	_, ok = wikiCloneURLForRepoInfo("https://github.com/owner/repo.wiki.git", repoInfo{name: "repo"})
	assert.False(t, ok)
}

func TestWikiWebURLForRepoInfo(t *testing.T) {
	info := repoInfo{owner: "owner", name: "repo"}

	assert.Equal(t, "https://github.com/owner/repo/wiki", wikiWebURLForRepoInfo("", info))
	assert.Equal(
		t,
		"https://github.company.local/owner/repo/wiki",
		wikiWebURLForRepoInfo("https://github.company.local/api/v3", info),
	)
}

func TestWikiWebURLForRepoCloneURL(t *testing.T) {
	got, err := wikiWebURLForRepoCloneURL("https://github.com/owner/repo.git")
	require.NoError(t, err)
	assert.Equal(t, "https://github.com/owner/repo/wiki", got)

	got, err = wikiWebURLForRepoCloneURL("https://github.com/owner/repo")
	require.NoError(t, err)
	assert.Equal(t, "https://github.com/owner/repo/wiki", got)
}

func TestHasURLScheme(t *testing.T) {
	assert.True(t, hasURLScheme("https://user:pass@github.com/owner/repo.git"))
	assert.True(t, hasURLScheme("ssh://git@github.com/owner/repo.git"))
	assert.False(t, hasURLScheme("git@github.com:owner/repo.git"))
	assert.False(t, hasURLScheme("owner/repo"))
}

func TestIsSCPStyleRepoURL(t *testing.T) {
	assert.True(t, isSCPStyleRepoURL("git@github.com:owner/repo.git"))
	assert.False(t, isSCPStyleRepoURL("ssh://git@github.com/owner/repo.git"))
	assert.False(t, isSCPStyleRepoURL("https://user:pass@github.com/owner/repo.git"))
	assert.False(t, isSCPStyleRepoURL("owner/repo"))
}

func TestEndpointHost(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		want     string
		wantOK   bool
	}{
		{name: "empty", endpoint: "", wantOK: false},
		{name: "cloud URL", endpoint: "https://api.github.com", want: "api.github.com", wantOK: true},
		{name: "cloud host", endpoint: "api.github.com", want: "api.github.com", wantOK: true},
		{name: "enterprise URL with path", endpoint: "https://github.example.com/api/v3", want: "github.example.com", wantOK: true},
		{name: "enterprise host with path", endpoint: "github.example.com/api/v3", want: "github.example.com", wantOK: true},
		{name: "host with port", endpoint: "https://github.example.com:8443/api/v3", want: "github.example.com:8443", wantOK: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := endpointHost(tt.endpoint)
			assert.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestIsGitHubCloudEndpoint(t *testing.T) {
	assert.True(t, isGitHubCloudEndpoint(""))
	assert.True(t, isGitHubCloudEndpoint("github.com"))
	assert.True(t, isGitHubCloudEndpoint("https://api.github.com"))
	assert.True(t, isGitHubCloudEndpoint("api.github.com"))
	assert.True(t, isGitHubCloudEndpoint("https://github.com:443"))
	assert.False(t, isGitHubCloudEndpoint("https://legithub.com/api/v3"))
	assert.False(t, isGitHubCloudEndpoint("https://github.example.com/api/v3"))
	assert.False(t, isGitHubCloudEndpoint("https://enterprise.example.com/api/github.com"))
	assert.False(t, isGitHubCloudEndpoint("https://github.com:8443/api/v3"))
}

func TestEndpointBaseURL(t *testing.T) {
	got, err := endpointBaseURL("https://github.example.com/api/v3")
	require.NoError(t, err)
	assert.Equal(t, "https://github.example.com", got.String())

	got, err = endpointBaseURL("github.example.com/api/v3")
	require.NoError(t, err)
	assert.Equal(t, "https://github.example.com", got.String())

	got, err = endpointBaseURL("ghe.example:8443/api/v3")
	require.NoError(t, err)
	assert.Equal(t, "https://ghe.example:8443", got.String())
}

func TestCanonicalAPIEndpoint(t *testing.T) {
	assert.Equal(t, cloudV3Endpoint, canonicalAPIEndpoint(""))
	assert.Equal(t, cloudV3Endpoint, canonicalAPIEndpoint("github.com"))
	assert.Equal(t, cloudV3Endpoint, canonicalAPIEndpoint("https://api.github.com"))
	assert.Equal(t, "https://github.example.com/api/v3", canonicalAPIEndpoint("github.example.com/api/v3"))
	assert.Equal(t, "https://github.example.com/api/v3", canonicalAPIEndpoint("https://github.example.com/api/v3"))
	assert.Equal(t, "https://github.com:8443/api/v3", canonicalAPIEndpoint("github.com:8443/api/v3"))
}

func TestRepoCloneURLForTargetEndpoint(t *testing.T) {
	got, err := repoCloneURLForTargetEndpoint("", "http://github.com/owner/repo.git")
	require.NoError(t, err)
	assert.Equal(t, "https://github.com/owner/repo.git", got)

	got, err = repoCloneURLForTargetEndpoint(cloudV3Endpoint, "https://github.com:443/owner/repo.git")
	require.NoError(t, err)
	assert.Equal(t, "https://github.com:443/owner/repo.git", got)

	got, err = repoCloneURLForTargetEndpoint("http://github.company/api/v3", "https://github.company/owner/repo.git")
	require.NoError(t, err)
	assert.Equal(t, "http://github.company/owner/repo.git", got)

	_, err = repoCloneURLForTargetEndpoint(cloudV3Endpoint, "https://attacker.example/owner/repo.git")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not match GitHub endpoint host")

	_, err = repoCloneURLForTargetEndpoint(cloudV3Endpoint, "ssh://git@github.com/owner/repo.git")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported scheme")
}

func TestIsWikiLink(t *testing.T) {
	assert.True(t, isWikiLink("https://github.com/owner/repo/wiki/path/to/file"))
	assert.False(t, isWikiLink("https://github.com/owner/repo/blob/main/path/to/file"))
	assert.False(t, isWikiLink("not a url"))
}
