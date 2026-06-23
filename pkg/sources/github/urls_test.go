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
	assert.Equal(
		t,
		"https://github.com/owner/repo.git",
		repoCloneURLForWikiCloneURL("https://github.com/owner/repo.wiki.git"),
	)
	assert.Equal(
		t,
		"https://github.com/owner/repo.git",
		repoCloneURLForWikiCloneURL("https://github.com/owner/repo.git"),
	)
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
	assert.False(t, isGitHubCloudEndpoint("https://legithub.com/api/v3"))
	assert.False(t, isGitHubCloudEndpoint("https://github.example.com/api/v3"))
	assert.False(t, isGitHubCloudEndpoint("https://enterprise.example.com/api/github.com"))
}

func TestEndpointBaseURL(t *testing.T) {
	got, err := endpointBaseURL("https://github.example.com/api/v3")
	require.NoError(t, err)
	assert.Equal(t, "https://github.example.com", got.String())

	got, err = endpointBaseURL("github.example.com/api/v3")
	require.NoError(t, err)
	assert.Equal(t, "https://github.example.com", got.String())
}

func TestCanonicalAPIEndpoint(t *testing.T) {
	assert.Equal(t, cloudV3Endpoint, canonicalAPIEndpoint(""))
	assert.Equal(t, cloudV3Endpoint, canonicalAPIEndpoint("github.com"))
	assert.Equal(t, cloudV3Endpoint, canonicalAPIEndpoint("https://api.github.com"))
	assert.Equal(t, "https://github.example.com/api/v3", canonicalAPIEndpoint("github.example.com/api/v3"))
	assert.Equal(t, "https://github.example.com/api/v3", canonicalAPIEndpoint("https://github.example.com/api/v3"))
}
