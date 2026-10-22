package github

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-github/v67/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

func TestNewInstallationGrants(t *testing.T) {
	tests := []struct {
		name             string
		perms            *github.InstallationPermissions
		wantIssues       bool
		wantPullRequests bool
	}{
		{name: "read grants", perms: &github.InstallationPermissions{Issues: github.String("read"), PullRequests: github.String("read")},
			wantIssues: true, wantPullRequests: true},
		{name: "write includes read", perms: &github.InstallationPermissions{Issues: github.String("write")},
			wantIssues: true},
		{name: "absent permissions aren't granted", perms: &github.InstallationPermissions{Contents: github.String("read")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := newInstallationGrants(7, tt.perms)

			require.NotNil(t, g)
			assert.Equal(t, int64(7), g.installationID)
			assert.Equal(t, tt.wantIssues, g.issuesGranted())
			assert.Equal(t, tt.wantPullRequests, g.pullRequestsGranted())
		})
	}
}

func TestNewInstallationGrants_TokenWithoutPermissionsIsUnknown(t *testing.T) {
	g := newInstallationGrants(7, nil)

	assert.Nil(t, g)
	assert.True(t, g.issuesGranted(), "unknown grants let listings run")
	assert.True(t, g.pullRequestsGranted(), "unknown grants let listings run")
}

func TestCommentGrantsForRepo_ReadsTheRepoInstallation(t *testing.T) {
	privKey := generateTestPrivateKey(t)
	var tokenPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token":       "test-token",
			"expires_at":  "2099-01-01T00:00:00Z",
			"permissions": map[string]string{"pull_requests": "read"},
		})
	}))
	defer server.Close()
	conn := &appConnector{
		apiEndpoint: server.URL, appID: 12345, appPrivateKey: string(privKey), installationID: 1,
		repoInstallationMap: map[string]int64{"https://github.com/o/r.git": 777},
	}
	s := &Source{connector: conn}

	grants := s.commentGrantsForRepo(context.Background(), "https://github.com/o/r.git")

	assert.Equal(t, "/api/v3/app/installations/777/access_tokens", tokenPath)
	assert.Equal(t, &installationGrants{installationID: 777, pullRequests: true}, grants)
}

func TestCommentGrantsForRepo_UnreadableGrantsAreUnknown(t *testing.T) {
	privKey := generateTestPrivateKey(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()
	s := &Source{connector: &appConnector{apiEndpoint: server.URL, appID: 12345, appPrivateKey: string(privKey), installationID: 1}}

	assert.Nil(t, s.commentGrantsForRepo(context.Background(), "https://github.com/o/r.git"))
}

func TestCommentGrantsForRepo_UnknownWithoutAppAuth(t *testing.T) {
	s := &Source{connector: &tokenConnector{}}

	assert.Nil(t, s.commentGrantsForRepo(context.Background(), "https://github.com/o/r.git"))
}
