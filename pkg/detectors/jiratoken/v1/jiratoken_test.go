package jiratoken

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
	validTokenPattern    = "Z7VoIYJ0K4rFWLBfkhOsLAWX"
	invalidTokenPattern  = "Z7VoI?J0K4rF#LBfkhO&LAWX"
	validDomainPattern   = "hereisavalidsubdomain.heresalongdomain.com"
	invalidDomainPattern = "?y4r3fs1ewqec12v1e3tl.5Hcsrcehic89saXd.ro@"
	validEmailPattern    = "xfkf_bz7@grum.com"
	invalidEmailPattern  = "xfKF_BZq7/grum.com"
	keyword              = "jira"
)

func TestJiraToken_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - with keyword jira",
			input: fmt.Sprintf("%s %s          \n%s %s\n%s %s", keyword, validTokenPattern, keyword, validDomainPattern, keyword, validEmailPattern),
			want:  []string{validEmailPattern + ":" + validTokenPattern + ":" + validDomainPattern},
		},
		{
			name:  "valid pattern - key out of prefix range",
			input: fmt.Sprintf("%s keyword is not close to the real key in the data\n = '%s' domain = '%s' email = '%s'", keyword, validTokenPattern, validDomainPattern, validEmailPattern),
			want:  []string{},
		},
		{
			name:  "invalid pattern",
			input: fmt.Sprintf("%s key = '%s' domain = '%s' email = '%s'", keyword, invalidTokenPattern, invalidDomainPattern, invalidEmailPattern),
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

func TestJiraToken_Verify(t *testing.T) {
	tests := []struct {
		name         string
		statusCode   int
		body         string
		wantVerified bool
	}{
		{
			name:         "authenticated user in body is verified",
			statusCode:   200,
			body:         `{"data":{"me":{"user":{"name":"Jira User"}}}}`,
			wantVerified: true,
		},
		{
			// A non-Atlassian host can happily return 200 with unrelated JSON, so the status code alone can't be trusted.
			name:         "200 without a jira user is not verified",
			statusCode:   200,
			body:         `{"method":"POST","host":"example.com"}`,
			wantVerified: false,
		},
		{
			name:         "unauthorized is not verified",
			statusCode:   401,
			body:         `{"code":401,"message":"Unauthorized"}`,
			wantVerified: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := common.ConstantResponseHttpClient(test.statusCode, test.body)
			verified, err := VerifyJiraToken(context.Background(), client, "user@example.com", "example.atlassian.net", validTokenPattern)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if verified != test.wantVerified {
				t.Errorf("got verified = %v, want %v", verified, test.wantVerified)
			}
		})
	}
}
