package firehydrant

import (
	"context"
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
			wantExtra:    map[string]string{"actor_name": "ci-bot", "actor_type": "bot", "organization": "Example"},
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
		{name: "malformed 200 body is still verified", body: `not json`, wantExtra: nil},
		{name: "empty 200 body is still verified", body: ``, wantExtra: nil},
		{name: "partial 200 body", body: `{"actor":{"name":"ci-bot"}}`, wantExtra: map[string]string{"actor_name": "ci-bot"}},
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
