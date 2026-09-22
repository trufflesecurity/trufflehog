package engine

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

// staticTokenSource returns the same token every time, bypassing any
// real IdP. This isolates the verifier's HTTP logic from token
// acquisition.
type staticTokenSource struct{ token string }

func (s *staticTokenSource) Token() (*oauth2.Token, error) {
	return &oauth2.Token{AccessToken: s.token, TokenType: "Bearer"}, nil
}

func testResult() *detectors.Result {
	return &detectors.Result{
		DetectorType: detector_typepb.DetectorType_CustomRegex,
		DetectorName: "TestDetector",
		Raw:          []byte("secret_value"),
	}
}

func cfgs(urls ...string) []OAuthVerifyConfig {
	out := make([]OAuthVerifyConfig, len(urls))
	for i, u := range urls {
		out[i] = OAuthVerifyConfig{Endpoint: u}
	}
	return out
}

// ─── Status code tests (default: no ranges configured) ───────────────

func TestOAuthVerify_Default200_Verified(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ts := &staticTokenSource{token: "test-token"}
	verified, err := OAuthVerify(context.Background(), nil, ts, cfgs(srv.URL), testResult())
	require.NoError(t, err)
	assert.True(t, verified)
}

func TestOAuthVerify_Default404_NotVerified(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	ts := &staticTokenSource{token: "test-token"}
	// Default non-200 continues to the next endpoint. With only one
	// endpoint, the loop exhausts — not verified, no error (the
	// endpoint responded, it just wasn't a 200).
	verified, err := OAuthVerify(context.Background(), nil, ts, cfgs(srv.URL), testResult())
	require.NoError(t, err)
	assert.False(t, verified)
}

func TestOAuthVerify_DefaultFallback_SecondEndpointVerifies(t *testing.T) {
	t.Parallel()
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ts := &staticTokenSource{token: "test-token"}
	// First endpoint returns 404 (non-200), second returns 200.
	// Without ranges, the default path should continue to the second.
	configs := cfgs(srv.URL+"/a", srv.URL+"/b")
	verified, err := OAuthVerify(context.Background(), nil, ts, configs, testResult())
	require.NoError(t, err)
	assert.True(t, verified)
	assert.Equal(t, 2, calls)
}

func TestOAuthVerify_NoEndpoints(t *testing.T) {
	t.Parallel()
	ts := &staticTokenSource{token: "test-token"}
	verified, err := OAuthVerify(context.Background(), nil, ts, nil, testResult())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no verification endpoints")
	assert.False(t, verified)
}

// ─── Status code range tests ────────────────────────────────────────

func TestOAuthVerify_SuccessRange_Verified(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated) // 201
	}))
	defer srv.Close()

	ts := &staticTokenSource{token: "test-token"}
	configs := []OAuthVerifyConfig{{
		Endpoint:      srv.URL,
		SuccessRanges: []string{"200-299"},
	}}
	verified, err := OAuthVerify(context.Background(), nil, ts, configs, testResult())
	require.NoError(t, err)
	assert.True(t, verified)
}

func TestOAuthVerify_RotatedRange(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusGone) // 410
	}))
	defer srv.Close()

	ts := &staticTokenSource{token: "test-token"}
	configs := []OAuthVerifyConfig{{
		Endpoint:      srv.URL,
		SuccessRanges: []string{"200-299"},
		RotatedRanges: []string{"410"},
	}}
	verified, err := OAuthVerify(context.Background(), nil, ts, configs, testResult())
	require.NoError(t, err)
	assert.False(t, verified)
}

func TestOAuthVerify_NeitherRange_TriesNext(t *testing.T) {
	t.Parallel()
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.WriteHeader(http.StatusInternalServerError) // 500
			return
		}
		w.WriteHeader(http.StatusOK) // 200
	}))
	defer srv.Close()

	ts := &staticTokenSource{token: "test-token"}
	configs := []OAuthVerifyConfig{
		{Endpoint: srv.URL + "/a", SuccessRanges: []string{"200-299"}, RotatedRanges: []string{"410"}},
		{Endpoint: srv.URL + "/b", SuccessRanges: []string{"200-299"}, RotatedRanges: []string{"410"}},
	}
	verified, err := OAuthVerify(context.Background(), nil, ts, configs, testResult())
	require.NoError(t, err)
	assert.True(t, verified)
	assert.Equal(t, 2, calls)
}

// ─── Request body template tests ────────────────────────────────────

func TestOAuthVerify_RequestBodyTemplate(t *testing.T) {
	t.Parallel()

	// Verify that the customer-defined body template is sent with
	// $token references resolved and hardcoded fields passed through.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var parsed map[string]string
		require.NoError(t, json.Unmarshal(body, &parsed))

		assert.Equal(t, "secret_value", parsed["credential"])
		assert.Equal(t, "CustomRegex", parsed["source"])
		assert.Equal(t, "production", parsed["environment"])
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ts := &staticTokenSource{token: "test-token"}
	configs := []OAuthVerifyConfig{{
		Endpoint:      srv.URL,
		SuccessRanges: []string{"200"},
		RequestBody: map[string]string{
			"credential":  "$secret",
			"source":      "$detector_type",
			"environment": "production",
		},
	}}
	verified, err := OAuthVerify(context.Background(), nil, ts, configs, testResult())
	require.NoError(t, err)
	assert.True(t, verified)
}

func TestOAuthVerify_RequestBodyWithTokenVar(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var parsed map[string]string
		require.NoError(t, json.Unmarshal(body, &parsed))

		// $token should resolve to the OAuth access token.
		assert.Equal(t, "my-jwt", parsed["auth_token"])
		assert.Equal(t, "secret_value", parsed["cred"])

		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ts := &staticTokenSource{token: "my-jwt"}
	configs := []OAuthVerifyConfig{{
		Endpoint:      srv.URL,
		SuccessRanges: []string{"200"},
		RequestBody: map[string]string{
			"cred":       "$secret",
			"auth_token": "$token",
		},
	}}
	verified, err := OAuthVerify(context.Background(), nil, ts, configs, testResult())
	require.NoError(t, err)
	assert.True(t, verified)
}

func TestOAuthVerify_DefaultBody_NoTemplate(t *testing.T) {
	t.Parallel()

	// Without a request body template, the raw secret is sent as the
	// body directly (not JSON-wrapped).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		assert.Equal(t, "secret_value", string(body))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ts := &staticTokenSource{token: "test-token"}
	verified, err := OAuthVerify(context.Background(), nil, ts, cfgs(srv.URL), testResult())
	require.NoError(t, err)
	assert.True(t, verified)
}

// ─── Single-range inference tests ───────────────────────────────────

func TestOAuthVerify_SuccessRangeOnly_NonMatch_NotVerified(t *testing.T) {
	t.Parallel()
	// Only successRanges configured; status doesn't match → not verified.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound) // 404
	}))
	defer srv.Close()

	ts := &staticTokenSource{token: "test-token"}
	configs := []OAuthVerifyConfig{{
		Endpoint:      srv.URL,
		SuccessRanges: []string{"200"},
	}}
	verified, err := OAuthVerify(context.Background(), nil, ts, configs, testResult())
	require.NoError(t, err)
	assert.False(t, verified)
}

func TestOAuthVerify_RotatedRangeOnly_NonMatch_Verified(t *testing.T) {
	t.Parallel()
	// Only rotatedRanges configured; status doesn't match → verified.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK) // 200
	}))
	defer srv.Close()

	ts := &staticTokenSource{token: "test-token"}
	configs := []OAuthVerifyConfig{{
		Endpoint:      srv.URL,
		RotatedRanges: []string{"410"},
	}}
	verified, err := OAuthVerify(context.Background(), nil, ts, configs, testResult())
	require.NoError(t, err)
	assert.True(t, verified)
}

// ─── Custom headers test ────────────────────────────────────────────

func TestOAuthVerify_CustomHeaders(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))
		assert.Equal(t, "custom-value", r.Header.Get("X-Custom"))
		assert.Equal(t, "another", r.Header.Get("X-Another"))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ts := &staticTokenSource{token: "test-token"}
	configs := []OAuthVerifyConfig{{
		Endpoint: srv.URL,
		Headers:  []string{"X-Custom: custom-value", "X-Another: another"},
	}}
	verified, err := OAuthVerify(context.Background(), nil, ts, configs, testResult())
	require.NoError(t, err)
	assert.True(t, verified)
}

// ─── Transport failure tests (Attempted field) ──────────────────────

func TestOAuthVerify_AllEndpointsFail_ReturnsError(t *testing.T) {
	t.Parallel()

	// Point at a listener that immediately closes connections.
	// Every endpoint fails at the transport level, so Attempted is
	// true but Definitive is false — OAuthVerify should return an error.
	ts := &staticTokenSource{token: "test-token"}
	configs := cfgs("http://127.0.0.1:1")
	verified, err := OAuthVerify(context.Background(), nil, ts, configs, testResult())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no endpoint gave a definitive answer")
	assert.False(t, verified)
}

// ─── Content-Type sniff tests ───────────────────────────────────────

func TestOAuthVerify_DefaultBody_ContentTypePlainText(t *testing.T) {
	t.Parallel()

	// Without a body template, raw secret bytes are sent. When the
	// raw secret isn't valid JSON, Content-Type defaults to text/plain.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "text/plain", r.Header.Get("Content-Type"))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ts := &staticTokenSource{token: "test-token"}
	verified, err := OAuthVerify(context.Background(), nil, ts, cfgs(srv.URL), testResult())
	require.NoError(t, err)
	assert.True(t, verified)
}

func TestOAuthVerify_TemplateBody_ContentTypeJSON(t *testing.T) {
	t.Parallel()

	// With a body template, ResolveRequestBody produces JSON.
	// Content-Type should default to application/json.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ts := &staticTokenSource{token: "test-token"}
	configs := []OAuthVerifyConfig{{
		Endpoint:    srv.URL,
		RequestBody: map[string]string{"secret": "$secret"},
	}}
	verified, err := OAuthVerify(context.Background(), nil, ts, configs, testResult())
	require.NoError(t, err)
	assert.True(t, verified)
}

func TestOAuthVerify_ExplicitContentType_Honored(t *testing.T) {
	t.Parallel()

	// An explicit Content-Type header takes priority over the sniff.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "application/xml", r.Header.Get("Content-Type"))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ts := &staticTokenSource{token: "test-token"}
	configs := []OAuthVerifyConfig{{
		Endpoint: srv.URL,
		Headers:  []string{"Content-Type: application/xml"},
	}}
	verified, err := OAuthVerify(context.Background(), nil, ts, configs, testResult())
	require.NoError(t, err)
	assert.True(t, verified)
}

func TestOAuthVerify_JSONPrimitive_ContentTypePlainText(t *testing.T) {
	t.Parallel()

	// A raw secret that is a valid JSON primitive (e.g. a quoted
	// string) should still get text/plain, not application/json.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "text/plain", r.Header.Get("Content-Type"))
		body, _ := io.ReadAll(r.Body)
		assert.Equal(t, `"some-api-key"`, string(body))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ts := &staticTokenSource{token: "test-token"}
	r := testResult()
	r.Raw = []byte(`"some-api-key"`)
	verified, err := OAuthVerify(context.Background(), nil, ts, cfgs(srv.URL), r)
	require.NoError(t, err)
	assert.True(t, verified)
}

// ─── Token acquisition failure tests ────────────────────────────────

// failingTokenSource always returns an error, simulating an unreachable
// IdP or bad credentials.
type failingTokenSource struct{}

func (f *failingTokenSource) Token() (*oauth2.Token, error) {
	return nil, assert.AnError
}

func TestOAuthVerify_TokenFailure_SkipsEndpoint(t *testing.T) {
	t.Parallel()

	// When the body template uses $token and token acquisition fails,
	// the endpoint should be skipped entirely — no request sent.
	var called bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ts := &failingTokenSource{}
	configs := []OAuthVerifyConfig{{
		Endpoint:      srv.URL,
		SuccessRanges: []string{"200"},
		RequestBody:   map[string]string{"cred": "$secret", "auth_token": "$token"},
	}}
	verified, err := OAuthVerify(context.Background(), nil, ts, configs, testResult())
	// Single endpoint skipped → Attempted but not Definitive → error.
	assert.Error(t, err)
	assert.False(t, verified)
	assert.False(t, called, "endpoint should not be contacted when token acquisition fails")
}
