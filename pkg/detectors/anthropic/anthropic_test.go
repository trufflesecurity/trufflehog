package anthropic

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestAnthropic_VerifyMatch(t *testing.T) {
	const key = "sk-ant-api03-Dtjm9IZ_rYhS_ihHLZmPXhjJ6PN8UPp7vNO7qO3735RRDpf8xbWGinsch0McONXznUm-4KWoA7WU2otvvwHBR5QRjiLakAA"

	tests := []struct {
		name         string
		statusCode   int
		body         string
		wantVerified bool
		wantErr      bool
		// wantErrContains, when set, must appear in the verification error. It pins that
		// the API's own explanation survives into the error rather than being discarded.
		wantErrContains string
	}{
		{
			name:         "200 is verified",
			statusCode:   http.StatusOK,
			body:         `{"data":[]}`,
			wantVerified: true,
		},
		{
			name:       "401 is determinate not-live",
			statusCode: http.StatusUnauthorized,
			body:       `{"type":"error","error":{"type":"authentication_error","message":"API key is invalid."}}`,
		},
		{
			name:       "404 is determinate not-live",
			statusCode: http.StatusNotFound,
			body:       `{"type":"error","error":{"type":"not_found_error","message":"Not found"}}`,
		},
		{
			// 400 is invalid_request_error: the API returns it for a malformed request,
			// never for the state of the key (bad keys return 401). It must stay
			// indeterminate, otherwise a request mangled in transit silently marks a live
			// key as not-verified.
			name:            "400 stays indeterminate and keeps the API message",
			statusCode:      http.StatusBadRequest,
			body:            `{"type":"error","error":{"type":"invalid_request_error","message":"anthropic-version: header is required"}}`,
			wantErr:         true,
			wantErrContains: "anthropic-version: header is required",
		},
		{
			name:            "429 stays indeterminate",
			statusCode:      http.StatusTooManyRequests,
			body:            `{"type":"error","error":{"type":"rate_limit_error","message":"Number of requests has exceeded your rate limit"}}`,
			wantErr:         true,
			wantErrContains: "rate_limit_error",
		},
		{
			name:       "500 stays indeterminate",
			statusCode: http.StatusInternalServerError,
			body:       `{"type":"error","error":{"type":"api_error","message":"Internal server error"}}`,
			wantErr:    true,
		},
		{
			// A gateway that returns a non-JSON body must still degrade to a plain
			// status-code error rather than panicking or losing the error entirely.
			name:            "unparseable body still yields an error",
			statusCode:      http.StatusBadRequest,
			body:            `<html>502 Bad Gateway</html>`,
			wantErr:         true,
			wantErrContains: "unexpected HTTP response status 400",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := common.ConstantResponseHttpClient(test.statusCode, test.body)

			verified, err := verifyAnthropicKey(context.Background(), client, apiKeyEndpoint, key)

			if test.wantErr {
				require.Error(t, err)
				if test.wantErrContains != "" {
					assert.Contains(t, err.Error(), test.wantErrContains)
				}
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, test.wantVerified, verified)
		})
	}
}

func TestAnthropic_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "valid pattern",
			input: `
				System Log - Authentication Token Issued
				Date: 2025-02-04 14:32:10 UTC
				Server: api-secure-03.internal
				Service: Anthropic API Gateway
				API Key: sk-ant-api03-abc123xyz-456def789ghij-klmnopqrstuvwx-3456yza789bcde-1234fghijklmnopby56aaaogaopaaaabc123xyzAA
				Admin Key: sk-ant-admin01-abc12fake-456def789ghij-klmnopqrstuvwx-3456yza789bcde-12fakehijklmnopby56aaaogaopaaaabc123xyzAA

				Log Entry:
				A new API and Admin key has been generated for service authentication. Please ensure that this key remains confidential and is not exposed in any public repositories or logs.
				`,
			want: []string{
				"sk-ant-api03-abc123xyz-456def789ghij-klmnopqrstuvwx-3456yza789bcde-1234fghijklmnopby56aaaogaopaaaabc123xyzAA",
				"sk-ant-admin01-abc12fake-456def789ghij-klmnopqrstuvwx-3456yza789bcde-12fakehijklmnopby56aaaogaopaaaabc123xyzAA",
			},
		},
		{
			name: "valid pattern - xml",
			input: `
				<com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
  					<scope>GLOBAL</scope>
  					<id>{anthropic}</id>
  					<secret>{AQAAABAAA sk-ant-api03-Dtjm9IZ_rYhS_ihHLZmPXhjJ6PN8UPp7vNO7qO3735RRDpf8xbWGinsch0McONXznUm-4KWoA7WU2otvvwHBR5QRjiLakAA}</secret>
  					<description>configuration for production</description>
					<creationDate>2023-05-18T14:32:10Z</creationDate>
  					<owner>jenkins-admin</owner>
				</com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
			`,
			want: []string{"sk-ant-api03-Dtjm9IZ_rYhS_ihHLZmPXhjJ6PN8UPp7vNO7qO3735RRDpf8xbWGinsch0McONXznUm-4KWoA7WU2otvvwHBR5QRjiLakAA"},
		},
		{
			name: "invalid pattern",
			input: `
				System Log - Authentication Token Issued
				Date: 2025-02-04 14:32:10 UTC
				Server: api-secure-03.internal
				Service: Anthropic API Gateway
				API Key: sk-ant-api03-abc123xyz-456de-klMnopqrstuvwx-3456yza789bcde-1234fghijklmnopAA

				Log Entry:
				A new API key has been generated for service authentication. Please ensure that this key remains confidential and is not exposed in any public repositories or logs.
				`,
			want: nil,
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
