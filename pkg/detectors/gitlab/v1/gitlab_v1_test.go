package gitlab

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestGitLab_Pattern(t *testing.T) {
	d := Scanner{}
	d.SetCloudEndpoint("https://gitlab.com")
	d.UseCloudEndpoint(true)
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "valid pattern",
			input: `[{
					"_id": "1a8d0cca-e1a9-4318-bc2f-f5658ab2dcb5",
					"name": "Gitlab",
					"type": "Detector",
					"api": true,
					"authentication_type": "",
					"verification_url": "https://api.example.com/example",
					"test_secrets": {
						"gitlab_secret": "oXCt4JT2wf1_WlZl2OVG"
					},
					"docs":"https://docs.gitlab.com/test/api/example.json#get-drone-test-example-settings", // this matches the pattern but fail in entropy check
					"expected_response": "200",
					"method": "GET",
					"deprecated": false
				}]`,
			want: []string{"oXCt4JT2wf1_WlZl2OVGhttps://gitlab.com"},
		},
		{
			name:  "valid pattern (with = before secret)",
			input: "GITLAB_TOKEN=ABc123456789dEFghIJK",
			want:  []string{"ABc123456789dEFghIJKhttps://gitlab.com"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 {
				t.Errorf("keywords '%v' not matched by: %s", d.Keywords(), test.input)
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			if err != nil {
				t.Errorf("error = %v", err)
				return
			}

			if len(results) != len(test.want) {
				if len(results) == 0 {
					t.Errorf("did not receive result")
				} else {
					t.Errorf("expected %d results, only received %d", len(test.want), len(results))
				}
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

func TestVerifyGitlab_Forbidden(t *testing.T) {
	tests := []struct {
		name          string
		body          string
		wantVerified  bool
		wantExtraData map[string]string
		wantErr       bool
	}{
		{
			name:         "blocked account",
			body:         `{"message":"403 Forbidden - Your account has been blocked."}`,
			wantVerified: true,
			wantExtraData: map[string]string{
				"access_denied_reason": "Your account has been blocked.",
				"blocked":              "True",
			},
		},
		{
			name:         "password expired",
			body:         `{"message":"403 Forbidden - Your password expired. Please access GitLab from a web browser to update your password."}`,
			wantVerified: true,
			wantExtraData: map[string]string{
				"access_denied_reason": "Your password expired. Please access GitLab from a web browser to update your password.",
			},
		},
		{
			name:         "unconfirmed email",
			body:         `{"message":"403 Forbidden - Your primary email address is not confirmed. Please check your inbox for the confirmation instructions."}`,
			wantVerified: true,
			wantExtraData: map[string]string{
				"access_denied_reason": "Your primary email address is not confirmed. Please check your inbox for the confirmation instructions.",
			},
		},
		{
			name:         "insufficient scope",
			body:         `{"error":"insufficient_scope","error_description":"The request requires higher privileges than provided by the access token.","scope":"read_user api read_api"}`,
			wantVerified: true,
		},
		{
			name:         "insufficient granular scope",
			body:         `{"error":"insufficient_granular_scope","error_description":"The request requires higher privileges than provided by the access token."}`,
			wantVerified: true,
		},
		{
			name:    "empty body",
			body:    "",
			wantErr: true,
		},
		{
			name:    "non-JSON body from a proxy or WAF",
			body:    "<html><body>403 Forbidden</body></html>",
			wantErr: true,
		},
		{
			name:    "JSON without a GitLab reason",
			body:    `{"message":"403 Forbidden"}`,
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := common.ConstantResponseHttpClient(403, test.body)
			verified, extraData, err := VerifyGitlab(context.Background(), client, "https://gitlab.com", "token")

			if (err != nil) != test.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, test.wantErr)
			}
			if verified != test.wantVerified {
				t.Errorf("verified = %v, want %v", verified, test.wantVerified)
			}
			if diff := cmp.Diff(test.wantExtraData, extraData); diff != "" {
				t.Errorf("extraData diff: (-want +got)\n%s", diff)
			}
		})
	}
}
