package github

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-github/v67/github"
	"github.com/shurcooL/githubv4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	trContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/credentialspb"
)

func generateTestPrivateKey(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
}

func TestAPIClientForInstallation(t *testing.T) {
	privKey := generateTestPrivateKey(t)

	var mu sync.Mutex
	var tokenRequestPaths []string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if r.Method == "POST" && strings.Contains(r.URL.Path, "access_tokens") {
			mu.Lock()
			tokenRequestPaths = append(tokenRequestPaths, r.URL.Path)
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"token":      "test-token",
				"expires_at": "2099-01-01T00:00:00Z",
			})
			return
		}

		// Default: return empty JSON array for any list endpoint.
		_ = json.NewEncoder(w).Encode([]interface{}{})
	}))
	defer server.Close()

	connector := &appConnector{
		appID:                   12345,
		appPrivateKey:           privKey,
		apiEndpoint:             server.URL,
		clientsByInstallationID: make(map[int64]*appInstallationClients),
	}

	t.Run("creates distinct clients for different installations", func(t *testing.T) {
		client1, err := connector.APIClientForInstallation(111)
		require.NoError(t, err)
		assert.NotNil(t, client1)

		client2, err := connector.APIClientForInstallation(222)
		require.NoError(t, err)
		assert.NotNil(t, client2)

		assert.NotSame(t, client1, client2, "should be different client instances")
	})

	t.Run("reuses clients for the same installation", func(t *testing.T) {
		client1, err := connector.APIClientForInstallation(333)
		require.NoError(t, err)
		client2, err := connector.APIClientForInstallation(333)
		require.NoError(t, err)

		assert.Same(t, client1, client2)
	})

	t.Run("returned client uses the correct installation ID", func(t *testing.T) {
		mu.Lock()
		tokenRequestPaths = nil
		mu.Unlock()

		client, err := connector.APIClientForInstallation(42)
		require.NoError(t, err)

		ctx := trContext.Background()
		_, _, _ = client.Organizations.ListMembers(ctx, "test-org", nil)

		mu.Lock()
		defer mu.Unlock()
		require.Len(t, tokenRequestPaths, 1)
		assert.Contains(t, tokenRequestPaths[0], "/app/installations/42/access_tokens")
	})

	t.Run("different installations use different tokens", func(t *testing.T) {
		mu.Lock()
		tokenRequestPaths = nil
		mu.Unlock()

		ctx := trContext.Background()

		client1, err := connector.APIClientForInstallation(100)
		require.NoError(t, err)
		_, _, _ = client1.Organizations.ListMembers(ctx, "org-a", nil)

		client2, err := connector.APIClientForInstallation(200)
		require.NoError(t, err)
		_, _, _ = client2.Organizations.ListMembers(ctx, "org-b", nil)

		mu.Lock()
		defer mu.Unlock()
		require.Len(t, tokenRequestPaths, 2)
		assert.Contains(t, tokenRequestPaths[0], "/installations/100/")
		assert.Contains(t, tokenRequestPaths[1], "/installations/200/")
	})
}

func TestNewAppConnectorDefaultAPIClientUsesConfiguredInstallation(t *testing.T) {
	privKey := generateTestPrivateKey(t)

	var mu sync.Mutex
	var tokenRequestPaths []string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if r.Method == "POST" && strings.Contains(r.URL.Path, "access_tokens") {
			mu.Lock()
			tokenRequestPaths = append(tokenRequestPaths, r.URL.Path)
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"token":      "configured-installation-token",
				"expires_at": "2099-01-01T00:00:00Z",
			})
			return
		}

		_ = json.NewEncoder(w).Encode([]map[string]string{{"login": "alice"}})
	}))
	defer server.Close()

	connector, err := NewAppConnector(trContext.Background(), server.URL, &credentialspb.GitHubApp{
		PrivateKey:     string(privKey),
		InstallationId: "4242",
		AppId:          "12345",
	})
	require.NoError(t, err)
	require.NotNil(t, connector.APIClient())
	require.NotNil(t, connector.GraphQLClient())

	gotAPIClient, err := connector.APIClientForRepo("https://github.com/default-org/repo.git")
	require.NoError(t, err)
	assert.Same(t, connector.APIClient(), gotAPIClient)

	gotGraphQLClient, err := connector.GraphQLClientForRepo(trContext.Background(), "https://github.com/default-org/repo.git")
	require.NoError(t, err)
	assert.Same(t, connector.GraphQLClient(), gotGraphQLClient)

	_, _, err = connector.APIClient().Organizations.ListMembers(trContext.Background(), "test-org", nil)
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, tokenRequestPaths, 1)
	assert.Contains(t, tokenRequestPaths[0], "/app/installations/4242/access_tokens")
}

func TestAPIClientForInstallationUsesConfiguredClient(t *testing.T) {
	defaultClient := github.NewClient(nil)
	connector := &appConnector{
		installationID: 100,
		clientsByInstallationID: map[int64]*appInstallationClients{
			100: {apiClient: defaultClient},
		},
	}

	got, err := connector.APIClientForInstallation(100)
	require.NoError(t, err)
	assert.Same(t, defaultClient, got)
}

func TestCloneUsesRepoInstallationMap(t *testing.T) {
	connector := &appConnector{
		installationID:      100,
		repoInstallationMap: make(map[string]int64),
	}

	t.Run("uses default installation when no mapping exists", func(t *testing.T) {
		installationID, mapped := connector.installationIDForRepo("https://github.com/default-org/repo.git")
		assert.False(t, mapped)
		assert.Equal(t, int64(100), installationID)
	})

	t.Run("uses mapped installation for cross-org repos", func(t *testing.T) {
		connector.setRepoInstallation("https://github.com/other-org/repo.git", 999)
		installationID, mapped := connector.installationIDForRepo("https://github.com/other-org/repo.git")
		assert.True(t, mapped)
		assert.Equal(t, int64(999), installationID)
	})

	t.Run("uses mapped installation for derived wiki URLs", func(t *testing.T) {
		connector.setRepoInstallation("https://github.com/wiki-org/repo.git", 888)
		installationID, mapped := connector.installationIDForRepo("https://github.com/wiki-org/repo.wiki.git")
		assert.True(t, mapped)
		assert.Equal(t, int64(888), installationID)
	})
}

func TestAPIClientForRepoUsesRepoInstallationMap(t *testing.T) {
	privKey := generateTestPrivateKey(t)

	var mu sync.Mutex
	var tokenRequestPaths []string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if r.Method == http.MethodPost && strings.Contains(r.URL.Path, "access_tokens") {
			mu.Lock()
			tokenRequestPaths = append(tokenRequestPaths, r.URL.Path)
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"token":      "test-token",
				"expires_at": "2099-01-01T00:00:00Z",
			})
			return
		}

		_ = json.NewEncoder(w).Encode([]map[string]string{{"login": "alice"}})
	}))
	defer server.Close()

	connector := &appConnector{
		installationID:          100,
		appID:                   12345,
		appPrivateKey:           privKey,
		apiEndpoint:             server.URL,
		clientsByInstallationID: make(map[int64]*appInstallationClients),
		repoInstallationMap:     make(map[string]int64),
	}
	connector.setRepoInstallation("https://github.com/other-org/repo.git", 999)

	client, err := connector.APIClientForRepo("https://github.com/other-org/repo.git")
	require.NoError(t, err)
	cachedClient, err := connector.APIClientForRepo("https://github.com/other-org/repo.git")
	require.NoError(t, err)
	assert.Same(t, client, cachedClient)

	_, _, _ = client.Organizations.ListMembers(trContext.Background(), "test-org", nil)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, tokenRequestPaths, 1)
	assert.Contains(t, tokenRequestPaths[0], "/app/installations/999/access_tokens")
}

func TestGraphQLClientForRepoCachesClients(t *testing.T) {
	privKey := generateTestPrivateKey(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{})
	}))
	defer server.Close()

	defaultGraphQLClient := &githubv4.Client{}
	connector := &appConnector{
		installationID: 100,
		appID:          12345,
		appPrivateKey:  privKey,
		apiEndpoint:    server.URL,
		clientsByInstallationID: map[int64]*appInstallationClients{
			100: {graphqlClient: defaultGraphQLClient},
		},
		repoInstallationMap: make(map[string]int64),
	}
	connector.setRepoInstallation("https://github.com/other-org/repo.git", 999)

	ctx := trContext.Background()

	t.Run("returns default client for default installation repos", func(t *testing.T) {
		got, err := connector.GraphQLClientForRepo(ctx, "https://github.com/default-org/repo.git")
		require.NoError(t, err)
		assert.Same(t, defaultGraphQLClient, got)
	})

	t.Run("caches clients for non-default installations", func(t *testing.T) {
		client1, err := connector.GraphQLClientForRepo(ctx, "https://github.com/other-org/repo.git")
		require.NoError(t, err)
		assert.NotSame(t, defaultGraphQLClient, client1)

		client2, err := connector.GraphQLClientForRepo(ctx, "https://github.com/other-org/repo.git")
		require.NoError(t, err)
		assert.Same(t, client1, client2)

		apiClient, err := connector.APIClientForRepo("https://github.com/other-org/repo.git")
		require.NoError(t, err)

		connector.mu.RLock()
		cachedClients := connector.clientsByInstallationID[999]
		connector.mu.RUnlock()
		require.NotNil(t, cachedClients)
		assert.Same(t, apiClient, cachedClients.apiClient)
		assert.Same(t, client1, cachedClients.graphqlClient)
	})
}

func TestDefaultConnectorsReturnDefaultClientsForRepo(t *testing.T) {
	ctx := trContext.Background()
	apiClient := github.NewClient(nil)
	graphqlClient := &githubv4.Client{}

	connectors := []Connector{
		&basicAuthConnector{apiClient: apiClient, graphqlClient: graphqlClient},
		&tokenConnector{apiClient: apiClient, graphqlClient: graphqlClient},
		&unauthenticatedConnector{apiClient: apiClient, graphqlClient: graphqlClient},
	}

	for _, connector := range connectors {
		gotAPIClient, err := connector.APIClientForRepo("https://github.com/trufflesecurity/trufflehog.git")
		require.NoError(t, err)
		assert.Same(t, apiClient, gotAPIClient)

		gotGraphQLClient, err := connector.GraphQLClientForRepo(ctx, "https://github.com/trufflesecurity/trufflehog.git")
		require.NoError(t, err)
		assert.Same(t, graphqlClient, gotGraphQLClient)
	}
}

func TestAddMembersByOrgWithClient(t *testing.T) {
	strPtr := func(s string) *string { return &s }
	memberPage := []*github.User{
		{Login: strPtr("alice")},
		{Login: strPtr("bob")},
		{Login: strPtr("charlie")},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(memberPage)
	}))
	defer server.Close()

	client, err := github.NewClient(nil).WithEnterpriseURLs(server.URL, server.URL)
	require.NoError(t, err)

	s := &Source{
		memberCache: make(map[string]struct{}),
	}

	ctx := trContext.Background()
	err = s.addMembersByOrgWithClient(ctx, client, "test-org", nil)
	require.NoError(t, err)

	assert.Len(t, s.memberCache, 3)
	assert.Contains(t, s.memberCache, "alice")
	assert.Contains(t, s.memberCache, "bob")
	assert.Contains(t, s.memberCache, "charlie")
}
