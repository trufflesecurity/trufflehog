package googleoauth2clientcredentials

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestGoogleOauth2ClientCredentials_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "typical pattern - with keyword oauth2_client_id",
			input: "oauth2_client_id = '1234567890-abc123def456ghi789jkl.apps.googleusercontent.com'",
			want: []string{
				"1234567890-abc123def456ghi789jkl.apps.googleusercontent.com",
			},
		},
		{
			name:  "typical pattern - with keyword oauth2_client_secret",
			input: "oauth2_client_secret = 'GOCSPX-5aBcD3fgHiJK_lMnOpQRs'",
			want: []string{
				"GOCSPX-5aBcD3fgHiJK_lMnOpQRs",
			},
		},
		{
			name: "typical pattern - multiline with both keywords",
			input: `oauth2_client_id = '1234567890-abc123def456ghi789jkl.apps.googleusercontent.com'
			oauth2_client_secret = 'GOCSPX-5aBcD3fgHiJK_lMnOpQRs'`,
			want: []string{
				"1234567890-abc123def456ghi789jkl.apps.googleusercontent.comGOCSPX-5aBcD3fgHiJK_lMnOpQRs",
			},
		},
		{
			name:  "typical pattern - invalid client secret",
			input: "oauth2_client_secret = 'GOCCCX-5aBcD3fgHiJK_lMnOpQRstuVwXyZ'",
			want:  nil,
		},
		{
			name:  "typical pattern - invalid client ID",
			input: "oauth2_client_id = '1234567890-abc123def456ghi789jkl0gmail.com'",
			want:  nil,
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

func TestGoogleOauth2ClientCredentials_Verify(t *testing.T) {
	input := `oauth2_client_id = '1234567890-abc123def456ghi789jkl.apps.googleusercontent.com'
	oauth2_client_secret = 'GOCSPX-5aBcD3fgHiJK_lMnOpQRs'`

	tests := []struct {
		name     string
		status   int
		body     string
		verified bool
		wantErr  bool
	}{
		{"valid client, bogus code", 400, `{"error":"invalid_grant","error_description":"Malformed auth code."}`, true, false},
		{"unknown client", 401, `{"error":"invalid_client","error_description":"The OAuth client was not found."}`, false, false},
		{"wrong secret", 401, `{"error":"invalid_client","error_description":"The provided client secret is invalid."}`, false, false},
		{"unexpected response", 500, `oops`, false, true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := Scanner{client: common.ConstantResponseHttpClient(test.status, test.body)}
			results, err := s.FromData(context.Background(), true, []byte(input))
			if err != nil || len(results) != 1 {
				t.Fatalf("results = %v, err = %v", results, err)
			}
			if results[0].Verified != test.verified {
				t.Errorf("Verified = %v, want %v", results[0].Verified, test.verified)
			}
			if (results[0].VerificationError() != nil) != test.wantErr {
				t.Errorf("VerificationError = %v, wantErr %v", results[0].VerificationError(), test.wantErr)
			}
		})
	}
}
