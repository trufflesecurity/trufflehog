package persona

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestPersona_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid sandbox key",
			input: `persona_api_key = "persona_sandbox_550e8400-e29b-41d4-a716-446655440000"`,
			want:  []string{"persona_sandbox_550e8400-e29b-41d4-a716-446655440000"},
		},
		{
			name:  "valid production key",
			input: `PERSONA_KEY=persona_production_abcdef01-2345-6789-abcd-ef0123456789`,
			want:  []string{"persona_production_abcdef01-2345-6789-abcd-ef0123456789"},
		},
		{
			name: "both keys in same input",
			input: `
				sandbox: persona_sandbox_550e8400-e29b-41d4-a716-446655440000
				production: persona_production_abcdef01-2345-6789-abcd-ef0123456789
			`,
			want: []string{
				"persona_sandbox_550e8400-e29b-41d4-a716-446655440000",
				"persona_production_abcdef01-2345-6789-abcd-ef0123456789",
			},
		},
		{
			name:  "truncated UUID - invalid",
			input: `key = persona_sandbox_550e8400-e29b-41d4-a716`,
			want:  nil,
		},
		{
			name:  "uppercase hex - invalid",
			input: `key = persona_sandbox_550E8400-E29B-41D4-A716-446655440000`,
			want:  nil,
		},
		{
			name:  "wrong prefix - invalid",
			input: `key = persona_staging_550e8400-e29b-41d4-a716-446655440000`,
			want:  nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 {
				if len(test.want) > 0 {
					t.Errorf("test %q failed: expected keywords %v to be found in the input", test.name, d.Keywords())
				}
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

func TestPersona_Verification(t *testing.T) {
	responseBody := `{"data":{"type":"api-key","id":"api_TvSRN76WJ6KsTzZFd4DEUDDF","attributes":{"name":"My Test Key","permissions":["account.read","inquiry.read","inquiry.write"],"expires_at":"2026-12-31T00:00:00.000Z"}}}`

	tests := []struct {
		name          string
		input         string
		client        *http.Client
		wantVerified  bool
		wantExtraData map[string]string
		wantErr       bool
	}{
		{
			name:  "verified with full response",
			input: "persona_production_abcdef01-2345-6789-abcd-ef0123456789",
			client: &http.Client{
				Transport: common.FakeTransport{
					CreateResponse: func(req *http.Request) (*http.Response, error) {
						resp := &http.Response{
							Request:    req,
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(strings.NewReader(responseBody)),
							Header:     make(http.Header),
						}
						resp.Header.Set("Persona-Organization-Id", "org_abc123")
						resp.Header.Set("Persona-Environment-Id", "env_xyz789")
						return resp, nil
					},
				},
			},
			wantVerified: true,
			wantExtraData: map[string]string{
				"Type":         "Production Key",
				"ID":           "api_TvSRN76WJ6KsTzZFd4DEUDDF",
				"Organization": "org_abc123",
				"Environment":  "env_xyz789",
				"Name":         "My Test Key",
				"Permissions":  "account.read, inquiry.read, inquiry.write",
				"Expires_At":   "2026-12-31T00:00:00.000Z",
			},
		},
		{
			name:  "verified sandbox key with minimal response",
			input: "persona_sandbox_abcdef01-2345-6789-abcd-ef0123456789",
			client: &http.Client{
				Transport: common.FakeTransport{
					CreateResponse: func(req *http.Request) (*http.Response, error) {
						return &http.Response{
							Request:    req,
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(strings.NewReader(`{"data":{"type":"api-key","id":"api_min123","attributes":{"permissions":["account.read"]}}}`)),
							Header:     make(http.Header),
						}, nil
					},
				},
			},
			wantVerified: true,
			wantExtraData: map[string]string{
				"Type":        "Sandbox Key",
				"ID":          "api_min123",
				"Permissions": "account.read",
			},
		},
		{
			name:         "unverified - 401",
			input:        "persona_production_abcdef01-2345-6789-abcd-ef0123456789",
			client:       common.ConstantResponseHttpClient(http.StatusUnauthorized, `{"errors":[{"title":"Must be authenticated"}]}`),
			wantVerified: false,
			wantExtraData: map[string]string{
				"Type": "Production Key",
			},
		},
		{
			name:         "unverified - 403",
			input:        "persona_production_abcdef01-2345-6789-abcd-ef0123456789",
			client:       common.ConstantResponseHttpClient(http.StatusForbidden, ""),
			wantVerified: false,
			wantExtraData: map[string]string{
				"Type": "Production Key",
			},
		},
		{
			name:         "error - unexpected status",
			input:        "persona_production_abcdef01-2345-6789-abcd-ef0123456789",
			client:       common.ConstantResponseHttpClient(http.StatusInternalServerError, ""),
			wantVerified: false,
			wantExtraData: map[string]string{
				"Type": "Production Key",
			},
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			d := Scanner{client: test.client}

			results, err := d.FromData(context.Background(), true, []byte(test.input))
			require.NoError(t, err)
			require.Len(t, results, 1)

			r := results[0]
			assert.Equal(t, test.wantVerified, r.Verified)
			assert.Equal(t, test.wantExtraData, r.ExtraData)

			if test.wantErr {
				assert.Error(t, r.VerificationError())
			} else {
				assert.NoError(t, r.VerificationError())
			}
		})
	}
}
