package verifierauth

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/custom_detectorspb"
)

// fakeIdP is a token endpoint that records each token request and answers
// with a configurable response.
type fakeIdP struct {
	*httptest.Server
	hits     atomic.Int32
	mu       sync.Mutex
	forms    []url.Values
	headers  []http.Header
	status   int
	response map[string]any
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	idp := &fakeIdP{
		status:   http.StatusOK,
		response: map[string]any{"access_token": "idp-token", "token_type": "Bearer", "expires_in": 3600},
	}
	idp.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		idp.hits.Add(1)
		_ = r.ParseForm()
		idp.mu.Lock()
		idp.forms = append(idp.forms, r.PostForm)
		idp.headers = append(idp.headers, r.Header.Clone())
		status, response := idp.status, idp.response
		idp.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(response)
	}))
	t.Cleanup(idp.Close)
	return idp
}

func (idp *fakeIdP) lastForm(t *testing.T) url.Values {
	t.Helper()
	idp.mu.Lock()
	defer idp.mu.Unlock()
	require.NotEmpty(t, idp.forms)
	return idp.forms[len(idp.forms)-1]
}

// recordingServer is a verification endpoint that records the headers of
// each request it receives.
type recordingServer struct {
	*httptest.Server
	mu      sync.Mutex
	headers []http.Header
}

func newRecordingServer(t *testing.T, handler http.HandlerFunc) *recordingServer {
	t.Helper()
	rs := &recordingServer{}
	rs.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rs.mu.Lock()
		rs.headers = append(rs.headers, r.Header.Clone())
		rs.mu.Unlock()
		if handler != nil {
			handler(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(rs.Close)
	return rs
}

func (rs *recordingServer) requests() []http.Header {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return append([]http.Header(nil), rs.headers...)
}

func ropcAuth(tokenEndpoint, tokenHeader string) *custom_detectorspb.VerifierAuth {
	return &custom_detectorspb.VerifierAuth{
		AuthConfig: &custom_detectorspb.VerifierAuth_Oauth2{
			Oauth2: &custom_detectorspb.OAuth2Config{
				TokenEndpoint: tokenEndpoint,
				TokenHeader:   tokenHeader,
				GrantConfig: &custom_detectorspb.OAuth2Config_Ropc{
					Ropc: &custom_detectorspb.ROPCConfig{
						Username:     "svc-scanner",
						Password:     "hunter2",
						ClientId:     "scanner-client",
						ClientSecret: "client-secret",
						Scope:        "verify",
					},
				},
			},
		},
	}
}

func mustConfig(t *testing.T, auth *custom_detectorspb.VerifierAuth) *Config {
	t.Helper()
	// The fake IdP is plain HTTP, so these tests opt into unsafe.
	cfg, err := FromProto(auth, true)
	require.NoError(t, err)
	require.NotNil(t, cfg)
	return cfg
}

// get sends a GET through client and drains and closes any response body
// itself. Only the request error is returned, because the tests assert on
// what the servers recorded rather than on the response.
func get(t *testing.T, client *http.Client, target string, header http.Header) error {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, target, nil)
	require.NoError(t, err)
	for k, vs := range header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	resp, err := client.Do(req)
	if resp != nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
	return err
}

func TestFromProto_NilAuthMeansNoAuth(t *testing.T) {
	cfg, err := FromProto(nil, false)
	assert.NoError(t, err)
	assert.Nil(t, cfg)
}

func TestFromProto_RejectsInvalidConfig(t *testing.T) {
	withRopc := func(mutate func(*custom_detectorspb.ROPCConfig)) *custom_detectorspb.VerifierAuth {
		auth := ropcAuth("https://idp.example.com/token", "")
		mutate(auth.GetOauth2().GetRopc())
		return auth
	}

	tests := []struct {
		name   string
		auth   *custom_detectorspb.VerifierAuth
		unsafe bool
	}{
		{name: "no mechanism", auth: &custom_detectorspb.VerifierAuth{}},
		{name: "empty token endpoint", auth: ropcAuth("", "")},
		{name: "http token endpoint without unsafe", auth: ropcAuth("http://idp.example.com/token", "")},
		{name: "invalid token header", auth: ropcAuth("https://idp.example.com/token", "Bad Header")},
		{
			name: "no grant",
			auth: &custom_detectorspb.VerifierAuth{AuthConfig: &custom_detectorspb.VerifierAuth_Oauth2{
				Oauth2: &custom_detectorspb.OAuth2Config{TokenEndpoint: "https://idp.example.com/token"},
			}},
		},
		{name: "missing username", auth: withRopc(func(r *custom_detectorspb.ROPCConfig) { r.Username = "" })},
		{name: "missing password", auth: withRopc(func(r *custom_detectorspb.ROPCConfig) { r.Password = "" })},
		{name: "missing client id", auth: withRopc(func(r *custom_detectorspb.ROPCConfig) { r.ClientId = "" })},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := FromProto(tt.auth, tt.unsafe)
			assert.Error(t, err)
			assert.Nil(t, cfg)
		})
	}
}

func TestFromProto_AllowsHTTPTokenEndpointWhenUnsafe(t *testing.T) {
	cfg, err := FromProto(ropcAuth("http://idp.example.com/token", ""), true)
	assert.NoError(t, err)
	assert.NotNil(t, cfg)
}

func TestFromProto_TokenHeaderDefaultsToAuthorizationAndIsCanonicalized(t *testing.T) {
	cfg := mustConfig(t, ropcAuth("https://idp.example.com/token", ""))
	assert.Equal(t, "Authorization", cfg.TokenHeader())

	cfg = mustConfig(t, ropcAuth("https://idp.example.com/token", "x-auth-proxy-token"))
	assert.Equal(t, "X-Auth-Proxy-Token", cfg.TokenHeader())
}

func TestFromProto_DoesNotFetchATokenUpFront(t *testing.T) {
	idp := newFakeIdP(t)
	mustConfig(t, ropcAuth(idp.URL, ""))
	assert.Zero(t, idp.hits.Load())
}

func TestROPCTokenSource_SendsPasswordGrantWithClientCredentialsInBody(t *testing.T) {
	idp := newFakeIdP(t)
	ropc := ropcAuth(idp.URL, "").GetOauth2().GetRopc()
	ts := newROPCTokenSource(idp.URL, ropc, idp.Client(), time.Now, logr.Discard)

	tok, err := ts.Token()
	require.NoError(t, err)
	assert.Equal(t, "idp-token", tok.AccessToken)

	form := idp.lastForm(t)
	assert.Equal(t, "password", form.Get("grant_type"))
	assert.Equal(t, "svc-scanner", form.Get("username"))
	assert.Equal(t, "hunter2", form.Get("password"))
	assert.Equal(t, "scanner-client", form.Get("client_id"))
	assert.Equal(t, "client-secret", form.Get("client_secret"))
	assert.Equal(t, "verify", form.Get("scope"))
	assert.Empty(t, idp.headers[0].Get("Authorization"), "client credentials must not be sent as basic auth")
}

func TestROPCTokenSource_ScopeHandling(t *testing.T) {
	tests := []struct {
		name      string
		scope     string
		wantScope string
		wantSent  bool
	}{
		{name: "multiple scopes are space separated", scope: "read  write", wantScope: "read write", wantSent: true},
		{name: "empty scope sends no scope parameter", scope: "", wantSent: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idp := newFakeIdP(t)
			ropc := ropcAuth(idp.URL, "").GetOauth2().GetRopc()
			ropc.Scope = tt.scope
			ts := newROPCTokenSource(idp.URL, ropc, idp.Client(), time.Now, logr.Discard)

			_, err := ts.Token()
			require.NoError(t, err)
			form := idp.lastForm(t)
			assert.Equal(t, tt.wantSent, form.Has("scope"))
			assert.Equal(t, tt.wantScope, form.Get("scope"))
		})
	}
}

func TestROPCTokenSource_DefaultExpiryWhenIdPOmitsExpiresIn(t *testing.T) {
	idp := newFakeIdP(t)
	idp.response = map[string]any{"access_token": "idp-token", "token_type": "Bearer"}
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	ropc := ropcAuth(idp.URL, "").GetOauth2().GetRopc()
	ts := newROPCTokenSource(idp.URL, ropc, idp.Client(), func() time.Time { return now }, logr.Discard)

	tok, err := ts.Token()
	require.NoError(t, err)
	assert.Equal(t, now.Add(defaultTokenLifetime), tok.Expiry)
}

func TestROPCTokenSource_ReturnsErrorOnRejectedCredentials(t *testing.T) {
	idp := newFakeIdP(t)
	idp.status = http.StatusUnauthorized
	idp.response = map[string]any{"error": "invalid_grant"}
	ropc := ropcAuth(idp.URL, "").GetOauth2().GetRopc()
	ts := newROPCTokenSource(idp.URL, ropc, idp.Client(), time.Now, logr.Discard)

	_, err := ts.Token()
	assert.Error(t, err)
}

func TestConfig_ReusesTokenUntilNearExpiry(t *testing.T) {
	tests := []struct {
		name      string
		expiresIn int
		wantHits  int32
	}{
		// ReuseTokenSource refreshes 10 seconds before expiry, so a token that
		// expires within that margin is treated as already stale.
		{name: "long-lived token is reused", expiresIn: 3600, wantHits: 1},
		{name: "token inside the refresh margin is refetched", expiresIn: 1, wantHits: 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idp := newFakeIdP(t)
			idp.response = map[string]any{"access_token": "idp-token", "token_type": "Bearer", "expires_in": tt.expiresIn}
			verifier := newRecordingServer(t, nil)
			cfg := mustConfig(t, ropcAuth(idp.URL, ""))
			client := cfg.WrapClient(verifier.Client(), []string{verifier.URL})

			for range 2 {
				err := get(t, client, verifier.URL+"/check", nil)
				require.NoError(t, err)
			}
			assert.Equal(t, tt.wantHits, idp.hits.Load())
		})
	}
}

func TestWrapClient_AttachesBearerTokenInDefaultHeader(t *testing.T) {
	idp := newFakeIdP(t)
	verifier := newRecordingServer(t, nil)
	cfg := mustConfig(t, ropcAuth(idp.URL, ""))
	client := cfg.WrapClient(verifier.Client(), []string{verifier.URL + "/base/path"})

	err := get(t, client, verifier.URL+"/other/path", nil)
	require.NoError(t, err)

	reqs := verifier.requests()
	require.Len(t, reqs, 1)
	assert.Equal(t, "Bearer idp-token", reqs[0].Get("Authorization"))
}

func TestWrapClient_CustomTokenHeaderLeavesDetectorAuthorizationUntouched(t *testing.T) {
	idp := newFakeIdP(t)
	verifier := newRecordingServer(t, nil)
	cfg := mustConfig(t, ropcAuth(idp.URL, "X-Auth-Proxy-Token"))
	client := cfg.WrapClient(verifier.Client(), []string{verifier.URL})

	err := get(t, client, verifier.URL, http.Header{"Authorization": {"Bearer secret-under-test"}})
	require.NoError(t, err)

	reqs := verifier.requests()
	require.Len(t, reqs, 1)
	assert.Equal(t, "Bearer secret-under-test", reqs[0].Get("Authorization"))
	assert.Equal(t, "Bearer idp-token", reqs[0].Get("X-Auth-Proxy-Token"))
}

func TestWrapClient_DoesNotAttachTokenToOtherHosts(t *testing.T) {
	idp := newFakeIdP(t)
	allowed := newRecordingServer(t, nil)
	other := newRecordingServer(t, nil)
	cfg := mustConfig(t, ropcAuth(idp.URL, "X-Auth-Proxy-Token"))
	client := cfg.WrapClient(http.DefaultClient, []string{allowed.URL})

	err := get(t, client, other.URL, nil)
	require.NoError(t, err)

	reqs := other.requests()
	require.Len(t, reqs, 1)
	assert.Empty(t, reqs[0].Get("X-Auth-Proxy-Token"))
	assert.Zero(t, idp.hits.Load(), "no token is needed for a host outside the allowlist")
}

func TestWrapClient_DoesNotCarryTokenAcrossRedirectToAnotherHost(t *testing.T) {
	idp := newFakeIdP(t)
	elsewhere := newRecordingServer(t, nil)
	allowed := newRecordingServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+"/landing", http.StatusFound)
	})
	cfg := mustConfig(t, ropcAuth(idp.URL, "X-Auth-Proxy-Token"))
	client := cfg.WrapClient(http.DefaultClient, []string{allowed.URL})

	err := get(t, client, allowed.URL, nil)
	require.NoError(t, err)

	require.Len(t, allowed.requests(), 1)
	assert.Equal(t, "Bearer idp-token", allowed.requests()[0].Get("X-Auth-Proxy-Token"))
	require.Len(t, elsewhere.requests(), 1)
	assert.Empty(t, elsewhere.requests()[0].Get("X-Auth-Proxy-Token"))
}

// headerCapture is a RoundTripper that records the headers of the request it
// is given and answers 200 without touching the network, so tests can use
// hosts and default ports that no local server listens on.
type headerCapture struct{ got http.Header }

func (c *headerCapture) RoundTrip(req *http.Request) (*http.Response, error) {
	c.got = req.Header.Clone()
	return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Request: req}, nil
}

func TestWrapClient_MatchesOriginsRegardlessOfDefaultPortSpelling(t *testing.T) {
	tests := []struct {
		name       string
		configured string
		request    string
		wantToken  bool
	}{
		{name: "https endpoint written with :443", configured: "https://proxy.example.com:443/base", request: "https://proxy.example.com/api", wantToken: true},
		{name: "https request written with :443", configured: "https://proxy.example.com/base", request: "https://proxy.example.com:443/api", wantToken: true},
		{name: "http endpoint written with :80", configured: "http://proxy.example.com:80", request: "http://proxy.example.com/api", wantToken: true},
		{name: "http request written with :80", configured: "http://proxy.example.com", request: "http://proxy.example.com:80/api", wantToken: true},
		{name: "IPv6 literal with default port", configured: "https://[2001:db8::1]:443", request: "https://[2001:db8::1]/api", wantToken: true},
		{name: "IPv6 literal with non-default port", configured: "https://[2001:db8::1]:8443", request: "https://[2001:db8::1]:8443/api", wantToken: true},
		{name: "non-default port must match exactly", configured: "https://proxy.example.com:8443", request: "https://proxy.example.com/api", wantToken: false},
		{name: "another scheme's default port is a different origin", configured: "https://proxy.example.com", request: "https://proxy.example.com:80/api", wantToken: false},
		{name: "http never matches an https endpoint", configured: "https://proxy.example.com", request: "http://proxy.example.com/api", wantToken: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idp := newFakeIdP(t)
			capture := &headerCapture{}
			cfg := mustConfig(t, ropcAuth(idp.URL, "X-Auth-Proxy-Token"))
			client := cfg.WrapClient(&http.Client{Transport: capture}, []string{tt.configured})

			err := get(t, client, tt.request, nil)
			require.NoError(t, err)

			if tt.wantToken {
				assert.Equal(t, "Bearer idp-token", capture.got.Get("X-Auth-Proxy-Token"))
			} else {
				assert.Empty(t, capture.got.Get("X-Auth-Proxy-Token"))
			}
		})
	}
}

func TestWrapClient_RefusesToOverwriteHeaderSetByDetector(t *testing.T) {
	idp := newFakeIdP(t)
	verifier := newRecordingServer(t, nil)
	cfg := mustConfig(t, ropcAuth(idp.URL, ""))
	client := cfg.WrapClient(verifier.Client(), []string{verifier.URL})

	err := get(t, client, verifier.URL, http.Header{"Authorization": {"Bearer secret-under-test"}})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrHeaderCollision)
	assert.Empty(t, verifier.requests(), "a colliding request must not be sent")
	assert.Zero(t, idp.hits.Load())
}

func TestWrapClient_TokenFailureFailsRequestWithoutSending(t *testing.T) {
	idp := newFakeIdP(t)
	idp.status = http.StatusUnauthorized
	idp.response = map[string]any{"error": "invalid_grant"}
	verifier := newRecordingServer(t, nil)
	cfg := mustConfig(t, ropcAuth(idp.URL, ""))
	client := cfg.WrapClient(verifier.Client(), []string{verifier.URL})

	err := get(t, client, verifier.URL, nil)
	var tokenErr *TokenError
	require.ErrorAs(t, err, &tokenErr)
	assert.Equal(t, cfg.trace, tokenErr.Trace)
	var retrieveErr *oauth2.RetrieveError
	assert.ErrorAs(t, tokenErr.Err, &retrieveErr, "the IdP's response is kept for callers that ask for it")
	assert.Empty(t, verifier.requests())
}

// Result.SetVerificationError reports only the innermost error of the chain
// http.Client returns, so that error must be the one naming verifier auth.
func TestWrapClient_AuthErrorsAreTheInnermostErrorOfTheRequestError(t *testing.T) {
	idp := newFakeIdP(t)
	idp.status = http.StatusUnauthorized
	idp.response = map[string]any{"error": "invalid_grant"}
	verifier := newRecordingServer(t, nil)
	cfg := mustConfig(t, ropcAuth(idp.URL, ""))
	client := cfg.WrapClient(verifier.Client(), []string{verifier.URL})

	innermost := func(err error) error {
		for errors.Unwrap(err) != nil {
			err = errors.Unwrap(err)
		}
		return err
	}

	err := get(t, client, verifier.URL, nil)
	assert.IsType(t, &TokenError{}, innermost(err))

	err = get(t, client, verifier.URL, http.Header{"Authorization": {"Bearer secret-under-test"}})
	leaf := innermost(err)
	assert.ErrorIs(t, leaf, ErrHeaderCollision)
	assert.Contains(t, leaf.Error(), `header "Authorization"`)
	assert.Contains(t, leaf.Error(), "oauth2_trace="+cfg.trace)
}

// Detectors read "dial tcp" or "no such host" in a request error, or a
// *net.DNSError in its chain, as "the verification host does not exist".
// An unreachable IdP must not trip those checks.
func TestWrapClient_UnreachableIdPErrorDoesNotLookLikeMissingVerificationHost(t *testing.T) {
	idp := newFakeIdP(t)
	idpURL := idp.URL
	idp.Close()
	verifier := newRecordingServer(t, nil)
	cfg := mustConfig(t, ropcAuth(idpURL, ""))
	client := cfg.WrapClient(verifier.Client(), []string{verifier.URL})

	err := get(t, client, verifier.URL, nil)
	var tokenErr *TokenError
	require.ErrorAs(t, err, &tokenErr)
	require.ErrorContains(t, tokenErr.Err, "dial tcp", "precondition: the cause is a network error")
	for _, marker := range []string{"no such host", "dial tcp", "connection refused"} {
		assert.NotContains(t, err.Error(), marker)
	}
	var opErr *net.OpError
	assert.False(t, errors.As(err, &opErr), "the IdP's network error must not be reachable through the chain")
	assert.Empty(t, verifier.requests())
}

func TestWrapClient_RepeatedTokenFailuresAreAnsweredFromCache(t *testing.T) {
	idp := newFakeIdP(t)
	idp.status = http.StatusUnauthorized
	idp.response = map[string]any{"error": "invalid_grant"}
	verifier := newRecordingServer(t, nil)
	cfg := mustConfig(t, ropcAuth(idp.URL, ""))
	client := cfg.WrapClient(verifier.Client(), []string{verifier.URL})

	for range 3 {
		err := get(t, client, verifier.URL, nil)
		assert.Error(t, err)
	}
	assert.Equal(t, int32(1), idp.hits.Load(), "failures inside the backoff window must not reach the IdP")
}

func TestWrapClient_DoesNotModifyBaseClient(t *testing.T) {
	base := &http.Client{Timeout: 7 * time.Second}
	cfg := mustConfig(t, ropcAuth("https://idp.example.com/token", ""))

	wrapped := cfg.WrapClient(base, []string{"https://verify.example.com"})
	assert.Nil(t, base.Transport)
	assert.Equal(t, 7*time.Second, wrapped.Timeout)
	assert.NotSame(t, base, wrapped)
}

// fakeClock is a manually advanced clock for tokenErrorCache tests.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// scriptedSource returns err (when non-nil) or a token, counting calls.
type scriptedSource struct {
	calls atomic.Int32
	mu    sync.Mutex
	err   error
	gate  chan struct{}
}

func (s *scriptedSource) Token() (*oauth2.Token, error) {
	s.calls.Add(1)
	if s.gate != nil {
		<-s.gate
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return nil, s.err
	}
	return &oauth2.Token{AccessToken: "tok"}, nil
}

func (s *scriptedSource) setErr(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.err = err
}

func TestTokenErrorCache_ReturnsCachedFailureWithinWindow(t *testing.T) {
	clock := &fakeClock{now: time.Unix(0, 0)}
	errIdP := errors.New("idp down")
	base := &scriptedSource{err: errIdP}
	cache := newTokenErrorCache(base, clock.Now, nil)

	_, err := cache.Token()
	require.ErrorIs(t, err, errIdP)

	clock.Advance(minTokenErrorBackoff - time.Second)
	_, err = cache.Token()
	assert.ErrorIs(t, err, errIdP, "cached error keeps the original cause")
	assert.Equal(t, int32(1), base.calls.Load())
}

func TestTokenErrorCache_RetriesAfterWindow(t *testing.T) {
	clock := &fakeClock{now: time.Unix(0, 0)}
	base := &scriptedSource{err: errors.New("idp down")}
	cache := newTokenErrorCache(base, clock.Now, nil)

	_, _ = cache.Token()
	clock.Advance(minTokenErrorBackoff)
	base.setErr(nil)

	tok, err := cache.Token()
	require.NoError(t, err)
	assert.Equal(t, "tok", tok.AccessToken)
	assert.Equal(t, int32(2), base.calls.Load())
}

func TestTokenErrorCache_WindowDoublesAndStopsAtCap(t *testing.T) {
	clock := &fakeClock{now: time.Unix(0, 0)}
	base := &scriptedSource{err: errors.New("idp down")}
	var windows []time.Duration
	cache := newTokenErrorCache(base, clock.Now, func(_ error, retryIn time.Duration) {
		windows = append(windows, retryIn)
	})

	for range 9 {
		_, _ = cache.Token()
		clock.Advance(maxTokenErrorBackoff)
	}

	assert.Equal(t, []time.Duration{
		5 * time.Second, 10 * time.Second, 20 * time.Second, 40 * time.Second, 80 * time.Second,
		160 * time.Second, 5 * time.Minute, 5 * time.Minute, 5 * time.Minute,
	}, windows)
}

func TestTokenErrorCache_SuccessResetsWindow(t *testing.T) {
	clock := &fakeClock{now: time.Unix(0, 0)}
	base := &scriptedSource{err: errors.New("idp down")}
	var windows []time.Duration
	cache := newTokenErrorCache(base, clock.Now, func(_ error, retryIn time.Duration) {
		windows = append(windows, retryIn)
	})

	_, _ = cache.Token()
	clock.Advance(maxTokenErrorBackoff)
	_, _ = cache.Token()
	clock.Advance(maxTokenErrorBackoff)

	base.setErr(nil)
	_, err := cache.Token()
	require.NoError(t, err)

	base.setErr(errors.New("idp down again"))
	_, _ = cache.Token()
	assert.Equal(t, []time.Duration{5 * time.Second, 10 * time.Second, 5 * time.Second}, windows)
}

func TestTokenErrorCache_ConcurrentCallersDuringFailureMakeOneFetch(t *testing.T) {
	clock := &fakeClock{now: time.Unix(0, 0)}
	gate := make(chan struct{})
	base := &scriptedSource{err: errors.New("idp down"), gate: gate}
	cache := newTokenErrorCache(base, clock.Now, nil)

	const callers = 20
	var wg sync.WaitGroup
	errs := make(chan error, callers)
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := cache.Token()
			errs <- err
		}()
	}
	// Let the single in-flight fetch fail; every other caller is queued on
	// the cache lock and then sees the open backoff window.
	close(gate)
	wg.Wait()
	close(errs)

	for err := range errs {
		assert.Error(t, err)
	}
	assert.Equal(t, int32(1), base.calls.Load())
}
