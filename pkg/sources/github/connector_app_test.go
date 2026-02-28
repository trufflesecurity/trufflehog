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

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/google/go-github/v67/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	trContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
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

	appsTransport, err := ghinstallation.NewAppsTransport(
		http.DefaultTransport,
		12345,
		privKey,
	)
	require.NoError(t, err)
	appsTransport.BaseURL = server.URL

	connector := &appConnector{
		appsTransport: appsTransport,
		apiEndpoint:   server.URL,
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
