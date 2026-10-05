package detectors

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/verifierauth"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/verifierauth/verifierauthtest"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/custom_detectorspb"
)

func TestEmbeddedEndpointSetter(t *testing.T) {
	type Scanner struct{ EndpointSetter }

	var s Scanner

	t.Run("useFoundEndpoints is true", func(t *testing.T) {
		s.useFoundEndpoints = true

		// "baz" is passed to Endpoints, should appear in the result
		assert.Equal(t, []string{"baz"}, s.Endpoints("baz"))
	})

	t.Run("setting configured endpoints", func(t *testing.T) {
		// Setting "foo" and "bar"
		assert.NoError(t, s.SetConfiguredEndpoints("foo", "bar"))

		// Returning error because no endpoints are passed
		assert.Error(t, s.SetConfiguredEndpoints())
	})

	// "foo" and "bar" are added as configured endpoint

	t.Run("useFoundEndpoints adds new endpoints", func(t *testing.T) {
		// "baz" is added because useFoundEndpoints is true
		assert.Equal(t, []string{"foo", "bar", "baz"}, s.Endpoints("baz"))
	})

	t.Run("useCloudEndpoint is true", func(t *testing.T) {
		s.useCloudEndpoint = true
		s.cloudEndpoint = "test"

		// "test" is added because useCloudEndpoint is true and cloudEndpoint is set
		assert.Equal(t, []string{"foo", "bar", "test"}, s.Endpoints())
	})

	t.Run("disable both foundEndpoints and cloudEndpoint", func(t *testing.T) {
		// now disable both useFoundEndpoints and useCloudEndpoint
		s.useFoundEndpoints = false
		s.useCloudEndpoint = false

		// "test" won't be added
		assert.Equal(t, []string{"foo", "bar"}, s.Endpoints("test"))
	})

	t.Run("cloudEndpoint not added when useCloudEndpoint is false", func(t *testing.T) {
		s.cloudEndpoint = "new"

		// "new" is not added because useCloudEndpoint is false
		assert.Equal(t, []string{"foo", "bar"}, s.Endpoints())
	})

}

// newTestVerifierAuth builds a verifier auth config backed by a fake IdP that
// always issues "idp-token".
func newTestVerifierAuth(t *testing.T, tokenHeader string) *verifierauth.Config {
	t.Helper()
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"idp-token","token_type":"Bearer","expires_in":3600}`))
	}))
	t.Cleanup(idp.Close)

	cfg, err := verifierauth.FromProto(&custom_detectorspb.VerifierAuth{
		AuthConfig: &custom_detectorspb.VerifierAuth_Oauth2{Oauth2: &custom_detectorspb.OAuth2Config{
			TokenEndpoint: idp.URL,
			TokenHeader:   tokenHeader,
			GrantConfig: &custom_detectorspb.OAuth2Config_Ropc{Ropc: &custom_detectorspb.ROPCConfig{
				Username: "svc", Password: "pw", ClientId: "client",
			}},
		}},
	}, true)
	require.NoError(t, err)
	return cfg
}

func TestEndpointSetter_VerifierAuthRestrictsEndpointsToConfigured(t *testing.T) {
	var s EndpointSetter
	require.NoError(t, s.SetConfiguredEndpoints("https://authproxy.example.com"))
	s.SetCloudEndpoint("https://api.example.com")
	s.UseCloudEndpoint(true)
	s.UseFoundEndpoints(true)
	require.Equal(t,
		[]string{"https://authproxy.example.com", "https://api.example.com", "https://found.example.com"},
		s.Endpoints("https://found.example.com"))

	s.SetVerifierAuth(newTestVerifierAuth(t, ""))
	assert.Equal(t, []string{"https://authproxy.example.com"}, s.Endpoints("https://found.example.com"))

	// Re-enabling public endpoints after auth is set must not bring them back.
	s.UseCloudEndpoint(true)
	s.UseFoundEndpoints(true)
	assert.Equal(t, []string{"https://authproxy.example.com"}, s.Endpoints("https://found.example.com"))

	// Clearing auth restores the normal endpoint rules.
	s.SetVerifierAuth(nil)
	assert.Equal(t,
		[]string{"https://authproxy.example.com", "https://api.example.com", "https://found.example.com"},
		s.Endpoints("https://found.example.com"))
}

func TestEndpointSetter_VerificationClientWithoutAuthReturnsBase(t *testing.T) {
	var s EndpointSetter
	base := &http.Client{}
	assert.Same(t, base, s.VerificationClient(base))
}

func TestEndpointSetter_VerificationClientAttachesTokenForConfiguredEndpoints(t *testing.T) {
	var gotToken, gotSecret string
	authProxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotToken = r.Header.Get("X-Auth-Proxy-Token")
		gotSecret = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(authProxy.Close)

	var s EndpointSetter
	require.NoError(t, s.SetConfiguredEndpoints(authProxy.URL))
	s.SetVerifierAuth(newTestVerifierAuth(t, "X-Auth-Proxy-Token"))

	req, err := http.NewRequest(http.MethodGet, authProxy.URL+"/api/v4/user", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer secret-under-test")
	resp, err := s.VerificationClient(authProxy.Client()).Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()

	assert.Equal(t, "Bearer idp-token", gotToken)
	assert.Equal(t, "Bearer secret-under-test", gotSecret)
}

// Detectors report a failed request through Result.SetVerificationError,
// which keeps only the innermost error's message. Verifier auth failures must
// survive that as a message that names verifier auth and carries the
// oauth2_trace, rather than as whatever the IdP or network returned.
func TestEndpointSetter_VerifierAuthFailuresSurviveSetVerificationError(t *testing.T) {
	var hits atomic.Int32
	authProxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(authProxy.Close)

	// verificationError sends a detector-style request through the wrapped
	// client and records the outcome the way a detector would.
	verificationError := func(t *testing.T, s *EndpointSetter, header http.Header) error {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, authProxy.URL+"/api/v4/user", nil)
		require.NoError(t, err)
		req.Header = header
		resp, err := s.VerificationClient(authProxy.Client()).Do(req)
		if resp != nil {
			_ = resp.Body.Close()
		}
		require.Error(t, err)

		var result Result
		result.SetVerificationError(err, "secret-under-test")
		return result.VerificationError()
	}

	t.Run("header collision", func(t *testing.T) {
		var s EndpointSetter
		require.NoError(t, s.SetConfiguredEndpoints(authProxy.URL))
		s.SetVerifierAuth(verifierauthtest.Config(t, verifierauthtest.NewIdP(t), ""))

		err := verificationError(t, &s, http.Header{"Authorization": {"Bearer secret-under-test"}})
		assert.ErrorContains(t, err, verifierauth.ErrHeaderCollision.Error())
		assert.ErrorContains(t, err, `header "Authorization"`)
		assert.ErrorContains(t, err, "oauth2_trace=")
		assert.NotContains(t, err.Error(), "secret-under-test")
	})

	t.Run("token unavailable", func(t *testing.T) {
		idp := verifierauthtest.NewIdP(t)
		idp.RejectCredentials()
		var s EndpointSetter
		require.NoError(t, s.SetConfiguredEndpoints(authProxy.URL))
		s.SetVerifierAuth(verifierauthtest.Config(t, idp, ""))

		err := verificationError(t, &s, http.Header{})
		assert.ErrorContains(t, err, "verifier auth: could not obtain access token")
		assert.ErrorContains(t, err, "oauth2_trace=")
		assert.NotContains(t, err.Error(), "invalid_grant", "the IdP's error stays in the logs")
	})

	assert.Zero(t, hits.Load(), "neither failure sends the request")
}
