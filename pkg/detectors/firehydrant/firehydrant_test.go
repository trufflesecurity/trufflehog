package firehydrant

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestFireHydrant_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - Claude Code permission allowlist",
			input: `"Bash(FIREHYDRANT_API_TOKEN=fhb-0a1b2c3d4e5f60718293a4b5c6d7e8f9 python3:*)",`,
			want:  []string{"fhb-0a1b2c3d4e5f60718293a4b5c6d7e8f9"},
		},
		{
			name: "valid pattern - env file",
			input: `
				FIREHYDRANT_API_KEY=fhb-1234567890abcdef1234567890abcdef
				OTHER_SETTING=true
			`,
			want: []string{"fhb-1234567890abcdef1234567890abcdef"},
		},
		{
			name:  "valid pattern - authorization header",
			input: `curl -H "Authorization: Bearer fhb-ffffffffffffffffffffffffffffffff" https://api.firehydrant.io/v1/ping`,
			want:  []string{"fhb-ffffffffffffffffffffffffffffffff"},
		},
		{
			name: "finds all matches",
			input: `
				[DEBUG] token=fhb-0a1b2c3d4e5f60718293a4b5c6d7e8f9
				[DEBUG] token=fhb-1234567890abcdef1234567890abcdef
			`,
			want: []string{"fhb-0a1b2c3d4e5f60718293a4b5c6d7e8f9", "fhb-1234567890abcdef1234567890abcdef"},
		},
		{
			name:  "invalid pattern - too short",
			input: `FIREHYDRANT_API_KEY=fhb-0a1b2c3d4e5f60718293a4b5c6d7e8f`,
			want:  []string{},
		},
		{
			name:  "invalid pattern - too long",
			input: `FIREHYDRANT_API_KEY=fhb-0a1b2c3d4e5f60718293a4b5c6d7e8f90`,
			want:  []string{},
		},
		{
			name:  "invalid pattern - uppercase hex",
			input: `FIREHYDRANT_API_KEY=fhb-0A1B2C3D4E5F60718293A4B5C6D7E8F9`,
			want:  []string{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 {
				t.Errorf("test %q failed: expected keywords %v to be found in the input", test.name, d.Keywords())
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			require.NoError(t, err)

			if len(results) != len(test.want) {
				t.Errorf("mismatch in result count: expected %d, got %d", len(test.want), len(results))
				return
			}

			actual := make(map[string]struct{}, len(results))
			for _, r := range results {
				if len(r.RawV2) > 0 {
					actual[string(r.RawV2)] = struct{}{}
				} else {
					actual[string(r.Raw)] = struct{}{}
				}
			}

			expected := make(map[string]struct{}, len(test.want))
			for _, v := range test.want {
				expected[v] = struct{}{}
			}

			if diff := cmp.Diff(expected, actual); diff != "" {
				t.Errorf("%s diff: (-want +got)\n%s", test.name, diff)
			}
		})
	}
}

func TestFireHydrant_Verify(t *testing.T) {
	key := "fhb-0a1b2c3d4e5f60718293a4b5c6d7e8f9"
	tests := []struct {
		name         string
		status       int
		body         string
		wantVerified bool
		wantErr      bool
		wantExtra    map[string]string
	}{
		{
			name:         "200 verified with actor and organization",
			status:       200,
			body:         `{"actor":{"name":"ci-bot","type":"bot"},"organization":{"name":"Example"}}`,
			wantVerified: true,
			wantExtra:    map[string]string{"actor_name": "ci-bot", "actor_type": "bot", "organization": "Example", "region": "us"},
		},
		{
			name:   "401 determinately unverified",
			status: 401,
			body:   `{"error":"The bearer token you provided is invalid or expired."}`,
		},
		{
			name:    "403 indeterminate",
			status:  403,
			body:    `{}`,
			wantErr: true,
		},
		{
			name:    "500 indeterminate",
			status:  500,
			body:    `{}`,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Scanner{client: common.ConstantResponseHttpClient(tt.status, tt.body)}
			results, err := s.FromData(context.Background(), true, []byte("FIREHYDRANT_API_KEY="+key))
			require.NoError(t, err)
			require.Len(t, results, 1)
			require.Equal(t, tt.wantVerified, results[0].Verified)
			require.Equal(t, tt.wantErr, results[0].VerificationError() != nil)
			require.Equal(t, tt.wantExtra, results[0].ExtraData)
		})
	}
}

func TestFireHydrant_VerifyEdgeCases(t *testing.T) {
	key := "fhb-0a1b2c3d4e5f60718293a4b5c6d7e8f9"
	tests := []struct {
		name      string
		body      string
		wantExtra map[string]string
	}{
		{name: "malformed 200 body is still verified", body: `not json`, wantExtra: map[string]string{"region": "us"}},
		{name: "empty 200 body is still verified", body: ``, wantExtra: map[string]string{"region": "us"}},
		{name: "partial 200 body", body: `{"actor":{"name":"ci-bot"}}`, wantExtra: map[string]string{"actor_name": "ci-bot", "region": "us"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Scanner{client: common.ConstantResponseHttpClient(200, tt.body)}
			results, err := s.FromData(context.Background(), true, []byte(key))
			require.NoError(t, err)
			require.Len(t, results, 1)
			require.True(t, results[0].Verified)
			require.NoError(t, results[0].VerificationError())
			require.Equal(t, tt.wantExtra, results[0].ExtraData)
		})
	}
}

func TestFireHydrant_Request(t *testing.T) {
	key := "fhb-0a1b2c3d4e5f60718293a4b5c6d7e8f9"
	var calls int
	client := &http.Client{Transport: common.FakeTransport{
		CreateResponse: func(req *http.Request) (*http.Response, error) {
			calls++
			require.Equal(t, http.MethodGet, req.Method)
			require.Equal(t, "https://api.firehydrant.io/v1/ping", req.URL.String())
			require.Equal(t, "Bearer "+key, req.Header.Get("Authorization"))
			return &http.Response{Request: req, StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{}`))}, nil
		},
	}}
	s := Scanner{client: client}
	// The same key twice is reported, and verified, once.
	results, err := s.FromData(context.Background(), true, []byte(key+" and again "+key))
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.Equal(t, 1, calls)
	require.Equal(t, map[string]string{"key": key}, results[0].SecretParts)
}

// TestFireHydrant_Regions checks that region-scoped keys are verified against both the US and EU
// hosts, and that a key is only determinately invalid when every region rejects it.
func TestFireHydrant_Regions(t *testing.T) {
	key := "fhb-0a1b2c3d4e5f60718293a4b5c6d7e8f9"
	const us, eu = "api.firehydrant.io", "api.eu.firehydrant.io"
	type reply struct {
		status int
		err    bool
	}
	tests := []struct {
		name         string
		replies      map[string]reply
		wantVerified bool
		wantErr      bool
		wantRegion   string
		wantHosts    []string
	}{
		{
			name:         "US key: verified on the first call, EU not tried",
			replies:      map[string]reply{us: {status: 200}},
			wantVerified: true, wantRegion: "us", wantHosts: []string{us},
		},
		{
			name:         "EU key: US 401, EU 200 is verified",
			replies:      map[string]reply{us: {status: 401}, eu: {status: 200}},
			wantVerified: true, wantRegion: "eu", wantHosts: []string{us, eu},
		},
		{
			name:      "both regions 401 is determinately invalid",
			replies:   map[string]reply{us: {status: 401}, eu: {status: 401}},
			wantHosts: []string{us, eu},
		},
		{
			name:      "US 401, EU 500 is indeterminate",
			replies:   map[string]reply{us: {status: 401}, eu: {status: 500}},
			wantErr:   true,
			wantHosts: []string{us, eu},
		},
		{
			name:      "US network error, EU 401 is indeterminate",
			replies:   map[string]reply{us: {err: true}, eu: {status: 401}},
			wantErr:   true,
			wantHosts: []string{us, eu},
		},
		{
			name:         "US network error, EU 200 is verified",
			replies:      map[string]reply{us: {err: true}, eu: {status: 200}},
			wantVerified: true, wantRegion: "eu", wantHosts: []string{us, eu},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var hosts []string
			client := &http.Client{Transport: common.FakeTransport{
				CreateResponse: func(req *http.Request) (*http.Response, error) {
					hosts = append(hosts, req.URL.Host)
					require.Equal(t, "/v1/ping", req.URL.Path)
					require.Equal(t, "Bearer "+key, req.Header.Get("Authorization"))
					r, ok := tt.replies[req.URL.Host]
					require.True(t, ok, "unexpected host %s", req.URL.Host)
					if r.err {
						return nil, errors.New("connection reset")
					}
					return &http.Response{Request: req, StatusCode: r.status, Body: io.NopCloser(strings.NewReader(`{}`))}, nil
				},
			}}
			s := Scanner{client: client}
			results, err := s.FromData(context.Background(), true, []byte(key))
			require.NoError(t, err)
			require.Len(t, results, 1)
			require.Equal(t, tt.wantVerified, results[0].Verified)
			require.Equal(t, tt.wantErr, results[0].VerificationError() != nil)
			require.Equal(t, tt.wantHosts, hosts)
			if tt.wantVerified {
				require.Equal(t, tt.wantRegion, results[0].ExtraData["region"])
			}
		})
	}
}

// From Stephen's review suggestion: an EU token (401 on US, 200 on EU) is verified, and the EU
// response's ExtraData is kept.
func TestFireHydrant_Verify_MultiRegion(t *testing.T) {
	key := "fhb-0a1b2c3d4e5f60718293a4b5c6d7e8f9"
	client := &http.Client{Transport: common.FakeTransport{
		CreateResponse: func(req *http.Request) (*http.Response, error) {
			if strings.Contains(req.URL.Host, "api.eu.") {
				return &http.Response{Request: req, StatusCode: http.StatusOK,
					Body: io.NopCloser(strings.NewReader(`{"organization":{"name":"EU Org"}}`))}, nil
			}
			return &http.Response{Request: req, StatusCode: http.StatusUnauthorized,
				Body: io.NopCloser(strings.NewReader(`{"error":"The bearer token you provided is invalid or expired."}`))}, nil
		},
	}}
	s := Scanner{client: client}
	results, err := s.FromData(context.Background(), true, []byte(key))
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.True(t, results[0].Verified, "EU token should be verified even if US endpoint returns 401")
	require.NoError(t, results[0].VerificationError())
	require.Equal(t, map[string]string{"organization": "EU Org", "region": "eu"}, results[0].ExtraData)
}
