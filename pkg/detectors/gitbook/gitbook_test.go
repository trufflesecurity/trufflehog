package gitbook

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

// Synthetic tokens in the exact shape GitBook issues. Not real credentials.
var (
	apiToken          = "gb_api_0123456789ABCDEFGHIJabcdefghijKLMNOPQRST"
	oauthAccessToken  = "gb_oauth_atok_Ab3-xY_9kLmNoPqRsTuVwXyZ0123456789abcdefghi"
	oauthRefreshToken = "gb_oauth_rtok_Zy9_wX-8jKlMnOpQrStUvWxY9876543210ABCDEFGHI"
	scimToken         = "gb_scim_Qw3-eR_4tYuIoPaSdFgHjKlZxCvBnM0123456789abc"
)

func TestGitBook_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  map[string]string
	}{
		{
			name:  "personal API token",
			input: `GITBOOK_API_TOKEN=` + apiToken,
			want:  map[string]string{apiToken: tokenTypeAPI},
		},
		{
			name:  "OAuth access and refresh tokens in JSON",
			input: `{"access_token":"` + oauthAccessToken + `","refresh_token":"` + oauthRefreshToken + `"}`,
			want: map[string]string{
				oauthAccessToken:  tokenTypeOAuthAccess,
				oauthRefreshToken: tokenTypeOAuthRefresh,
			},
		},
		{
			name:  "SCIM token at end of input",
			input: `scim bearer token: ` + scimToken,
			want:  map[string]string{scimToken: tokenTypeSCIM},
		},
		{
			name:  "tokens separated by a single character",
			input: apiToken + "," + oauthAccessToken + "," + scimToken,
			want: map[string]string{
				apiToken:         tokenTypeAPI,
				oauthAccessToken: tokenTypeOAuthAccess,
				scimToken:        tokenTypeSCIM,
			},
		},
		{
			name:  "API token too long",
			input: `GITBOOK_API_TOKEN=` + apiToken + `X`,
		},
		{
			name:  "API token too short",
			input: `GITBOOK_API_TOKEN=` + apiToken[:len(apiToken)-1],
		},
		{
			name:  "OAuth token too long",
			input: `token=` + oauthAccessToken + `-`,
		},
		{
			name:  "OAuth authorization code is short-lived and ignored",
			input: `code=gb_oauth_code_Ab3-xY_9kLmNoPqRsTuVwXyZ0123456789abcdefghi`,
		},
		{
			name:  "OAuth client ID is not a secret",
			input: `client_id=gb_oauth_Ab3xY9kLmNoPqRsTuVwXyZ0123456789abcd`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 {
				t.Fatalf("keywords '%v' not matched by: %s", d.Keywords(), test.input)
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			if err != nil {
				t.Fatalf("FromData: %v", err)
			}

			got := make(map[string]string, len(results))
			for _, r := range results {
				if r.SecretParts["key"] != string(r.Raw) {
					t.Errorf("SecretParts[key] = %q, want %q", r.SecretParts["key"], r.Raw)
				}
				got[string(r.Raw)] = r.ExtraData["token_type"]
			}
			want := test.want
			if want == nil {
				want = map[string]string{}
			}
			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("(-want +got)\n%s", diff)
			}
		})
	}
}

func TestGitBook_IsFalsePositive(t *testing.T) {
	tests := []struct {
		name  string
		token string
		want  bool
	}{
		{name: "random token containing a word", token: "gb_oauth_atok_q7Vh2-HelloWz9_Kp4Rm8Tn3Jx6Ld1Fy5Bc0Gs2Nq7Pv4X", want: false},
		{name: "placeholder token", token: "gb_api_exampleExampleExampleExampleExample0", want: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, _ := Scanner{}.IsFalsePositive(detectors.Result{Raw: []byte(test.token)})
			if got != test.want {
				t.Errorf("IsFalsePositive = %v, want %v", got, test.want)
			}
		})
	}
}
