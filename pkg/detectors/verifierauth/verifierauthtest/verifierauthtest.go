// Package verifierauthtest supports tests outside verifierauth that exercise
// the verifier auth path: a fake OAuth2 identity provider that issues a fixed
// access token, and a helper that builds a verifierauth.Config against it.
// It is imported only from tests, so it never ends up in the binary.
package verifierauthtest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/verifierauth"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/custom_detectorspb"
)

// AccessToken is the access token the fake IdP issues. Verification servers
// in tests expect it as "Bearer " + AccessToken in the configured header.
const AccessToken = "auth-proxy-access-token"

// IdP is a fake OAuth2 token endpoint for the ROPC grant. It answers every
// token request with AccessToken until RejectCredentials is called.
type IdP struct {
	*httptest.Server
	hits     atomic.Int32
	rejected atomic.Bool
}

// NewIdP starts a fake IdP that is closed when the test ends.
func NewIdP(t testing.TB) *IdP {
	t.Helper()
	idp := &IdP{}
	idp.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		idp.hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if idp.rejected.Load() {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "invalid_grant"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": AccessToken,
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	t.Cleanup(idp.Close)
	return idp
}

// RejectCredentials makes every later token request fail with invalid_grant,
// which is how an IdP answers wrong service account credentials.
func (idp *IdP) RejectCredentials() { idp.rejected.Store(true) }

// Hits reports how many token requests the IdP has received.
func (idp *IdP) Hits() int { return int(idp.hits.Load()) }

// Config builds a verifier auth config that fetches tokens from idp and
// writes them to tokenHeader (empty means the default, Authorization). The
// fake IdP is plain HTTP, so the config is built with unsafe set.
func Config(t testing.TB, idp *IdP, tokenHeader string) *verifierauth.Config {
	t.Helper()
	cfg, err := verifierauth.FromProto(&custom_detectorspb.VerifierAuth{
		AuthConfig: &custom_detectorspb.VerifierAuth_Oauth2{
			Oauth2: &custom_detectorspb.OAuth2Config{
				TokenEndpoint: idp.URL,
				TokenHeader:   tokenHeader,
				GrantConfig: &custom_detectorspb.OAuth2Config_Ropc{
					Ropc: &custom_detectorspb.ROPCConfig{
						Username: "svc-scanner",
						Password: "svc-password",
						ClientId: "scanner-client",
					},
				},
			},
		},
	}, true)
	if err != nil {
		t.Fatalf("building verifier auth config: %v", err)
	}
	return cfg
}
