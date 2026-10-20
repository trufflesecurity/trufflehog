package github

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-github/v67/github"
	"github.com/stretchr/testify/require"
)

func TestAccessTokenForInstallation(t *testing.T) {
	privKey := generateTestPrivateKey(t)

	accessTokenServer := func(accessTokenHandler func(w http.ResponseWriter, r *http.Request)) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")

			if r.Method == "POST" && strings.Contains(r.URL.Path, "access_tokens") {
				accessTokenHandler(w, r)
				return
			}

			// Default: return empty JSON array for any list endpoint.
			_ = json.NewEncoder(w).Encode([]interface{}{})
		}))
	}

	t.Run("invalid", func(t *testing.T) {
		cs := &AppInstallationClients{InstallationID: 0}
		_, err := cs.AccessToken(t.Context())
		require.Error(t, err)
	})

	t.Run("success", func(t *testing.T) {
		server := accessTokenServer(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"token":      "test-token",
				"expires_at": "2099-01-01T00:00:00Z",
			})
		})
		defer server.Close()

		cs, err := GetAppInstallationClients(t.Context(), server.URL, 12345, string(privKey), 100)
		require.NoError(t, err)

		_, err = cs.AccessToken(t.Context())
		require.NoError(t, err)
	})

	t.Run("granted permissions come from the token", func(t *testing.T) {
		var hits atomic.Int64
		server := accessTokenServer(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"token":       "test-token",
				"expires_at":  "2099-01-01T00:00:00Z",
				"permissions": map[string]string{"issues": "read", "contents": "read"},
			})
		})
		defer server.Close()

		cs, err := GetAppInstallationClients(t.Context(), server.URL, 12345, string(privKey), 100)
		require.NoError(t, err)

		perms, err := cs.GrantedPermissions(t.Context())
		require.NoError(t, err)
		require.Equal(t, "read", perms.GetIssues())
		require.Empty(t, perms.GetPullRequests())

		_, err = cs.AccessToken(t.Context())
		require.NoError(t, err)
		require.Equal(t, int64(1), hits.Load(), "permissions and clone share one token")
	})

	t.Run("granted permissions without a token", func(t *testing.T) {
		cs := &AppInstallationClients{InstallationID: 0}
		_, err := cs.GrantedPermissions(t.Context())
		require.Error(t, err)
	})

	t.Run("rate limit", func(t *testing.T) {
		server := accessTokenServer(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Add("X-RateLimit-Remaining", "0")
			w.WriteHeader(http.StatusForbidden)

			_ = json.NewEncoder(w).Encode(map[string]interface{}{})
		})
		defer server.Close()

		cs, err := GetAppInstallationClients(t.Context(), server.URL, 12345, string(privKey), 100)
		require.NoError(t, err)

		_, err = cs.AccessToken(t.Context())
		require.Error(t, err)

		var gherr *github.RateLimitError
		require.ErrorAs(t, err, &gherr)
	})

	t.Run("not found / no installation", func(t *testing.T) {
		server := accessTokenServer(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)

			_ = json.NewEncoder(w).Encode(map[string]interface{}{})
		})
		defer server.Close()

		cs, err := GetAppInstallationClients(t.Context(), server.URL, 12345, string(privKey), 100)
		require.NoError(t, err)

		_, err = cs.AccessToken(t.Context())
		require.Error(t, err)
	})

	t.Run("reuse", func(t *testing.T) {
		var hits atomic.Int64

		server := accessTokenServer(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"token":      "test-token",
				"expires_at": "2099-01-01T00:00:00Z",
			})
		})
		defer server.Close()

		cs, err := GetAppInstallationClients(t.Context(), server.URL, 12345, string(privKey), 100)
		require.NoError(t, err)

		_, err = cs.AccessToken(t.Context())
		require.NoError(t, err)

		_, err = cs.AccessToken(t.Context())
		require.NoError(t, err)

		require.Equal(t, int64(1), hits.Load())
	})

	t.Run("expire", func(t *testing.T) {
		var hits atomic.Int64
		server := accessTokenServer(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"token":      "test-token",
				"expires_at": "2099-01-01T00:00:00Z",
			})
		})
		defer server.Close()

		cs, err := GetAppInstallationClients(t.Context(), server.URL, 12345, string(privKey), 100)
		require.NoError(t, err)

		_, err = cs.AccessToken(t.Context())
		require.NoError(t, err)

		token := cs.accessTokenIfValid()
		require.NotNil(t, token)

		token.ExpiresAt = &github.Timestamp{Time: time.Now()}

		token = cs.accessTokenIfValid()
		require.Nil(t, token)

		// race these for good measure
		var wg sync.WaitGroup
		for range 3 {
			wg.Go(func() {
				_, err := cs.AccessToken(t.Context())
				require.NoError(t, err)
			})
		}
		wg.Wait()

		token = cs.accessTokenIfValid()
		require.NotNil(t, token)

		require.Equal(t, int64(2), hits.Load())
	})
}
