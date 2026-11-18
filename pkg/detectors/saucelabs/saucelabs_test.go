package saucelabs

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validUsername   = "nBpeh2YF3tjMNmKAUHrDpfXJZJ.ZUhWmObRC735zdh99LeJh4Kcr_2"
	invalidUsername = "?Bpeh?YF3tjMNmKAUHrDpfXJZJ.ZUhWmObRC735zdh99LeJh4Kcr_2"
	validKey        = "9toqmh6r-g2ly-k3fr-fiyr-5jnnewlxy3u9"
	invalidKey      = "9toqmh6r?g2ly-k3fr-fiyr-5jnnewlxy3u9"
	validBaseUrl    = "api.eu-west-0.saucelabs.com"
	invalidBaseUrl  = "?pi.eu-west-0,saucelabs.co?"
	keyword         = "saucelabs"
)

func TestSauceLabs_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - with keyword saucelabs",
			input: fmt.Sprintf("%s token - '%s'\n%s token - '%s'\n%s token - '%s'\n", keyword, validUsername, keyword, validKey, keyword, validBaseUrl),
			want:  []string{".com" + validKey, "token" + validKey},
		},
		{
			name:  "invalid pattern",
			input: fmt.Sprintf("%s token - '%s'\n%s token - '%s'\n%s token - '%s'\n", keyword, invalidUsername, keyword, invalidKey, keyword, invalidBaseUrl),
			want:  []string{},
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

func TestSauceLabs_BaseURL(t *testing.T) {
	tests := []struct {
		name    string
		baseURL string
		want    string
	}{
		{
			name:    "regional host",
			baseURL: "api.eu-central-1.saucelabs.com",
			want:    "api.eu-central-1.saucelabs.com",
		},
		{
			name:    "lookalike host falls back to default",
			baseURL: "api.us-west-1-saucelabs.com",
			want:    fixedBaseURL,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data := fmt.Sprintf("saucelabs_username: john.smith\nsaucelabs_key: %s\nurl: %s\n", validKey, test.baseURL)
			results, err := Scanner{}.FromData(context.Background(), false, []byte(data))
			if err != nil {
				t.Fatalf("error = %v", err)
			}
			if len(results) == 0 {
				t.Fatal("did not receive result")
			}
			for _, r := range results {
				if got := r.ExtraData["Base URL"]; got != test.want {
					t.Errorf("Base URL = %q, want %q", got, test.want)
				}
			}
		})
	}
}

func TestVerifySauceLabKey(t *testing.T) {
	const username = "john.smith"

	tests := []struct {
		name         string
		status       int
		body         string
		wantVerified bool
		wantErr      bool
	}{
		{
			name:         "valid user credential",
			status:       200,
			body:         `{"sub":"usr_7c21e3a0","username":"john.smith","organization":"9f3b2a17","auth_method":"basic","credential_id":"cred_7c21e3a0"}`,
			wantVerified: true,
		},
		{
			name:         "valid service account credential",
			status:       200,
			body:         `{"sub":"sa_1234","username":"bot-automation-service-account-d2164","organization":"9f3b2a17","auth_method":"basic","credential_id":"cred_1234"}`,
			wantVerified: true,
		},
		{
			name:    "200 with HTML body from a proxy",
			status:  200,
			body:    "<html><body>Access to this site is blocked</body></html>",
			wantErr: true,
		},
		{
			name:    "200 with unrelated JSON",
			status:  200,
			body:    `{"status":"ok"}`,
			wantErr: true,
		},
		{
			name:    "200 with empty JSON object",
			status:  200,
			body:    `{}`,
			wantErr: true,
		},
		{
			name:   "invalid credential",
			status: 401,
			body:   `{"detail":"Unauthorized"}`,
		},
		{
			name:    "403 from a proxy",
			status:  403,
			body:    "<html><body>403 Forbidden</body></html>",
			wantErr: true,
		},
		{
			name:    "403 with empty body",
			status:  403,
			wantErr: true,
		},
		{
			name:    "server error",
			status:  500,
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := common.ConstantResponseHttpClient(test.status, test.body)
			verified, err := verifySauceLabKey(context.Background(), client, username, validKey, fixedBaseURL)

			if (err != nil) != test.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, test.wantErr)
			}
			if verified != test.wantVerified {
				t.Errorf("verified = %v, want %v", verified, test.wantVerified)
			}
		})
	}
}

func TestSauceLabs_FromData_ProxyForbidden(t *testing.T) {
	s := Scanner{client: common.ConstantResponseHttpClient(403, "<html><body>403 Forbidden</body></html>")}
	data := fmt.Sprintf("saucelabs_username: john.smith\nsaucelabs_key: %s\n", validKey)

	results, err := s.FromData(context.Background(), true, []byte(data))
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if len(results) == 0 {
		t.Fatal("did not receive result")
	}
	for _, r := range results {
		if r.Verified {
			t.Errorf("result %q verified from a proxy 403", r.RawV2)
		}
		if r.VerificationError() == nil {
			t.Errorf("result %q has no verification error for a proxy 403", r.RawV2)
		}
	}
}
