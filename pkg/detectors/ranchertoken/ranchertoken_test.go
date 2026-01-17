package ranchertoken

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestRancherToken_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	// Test tokens - all 54 characters (lowercase alphanumeric)
	token54a := "jswpl27hs8pd88rmw2mgfgrjtpljp85fd5v7rhdwr2s6z22hvt6vjt"           // 54 chars
	token54b := "k7mnp9qr4st2vwx8yz3abc5def1ghi6jkl0mno8pqr2stu4vwx9yz1"           // 54 chars (added 1)
	token54c := "xz9yw8vt7sr6qp5on4ml3kj2ih1gf0ed9cb8az7yx6wv5ut4sr3qp1"           // 54 chars (added 1)
	token54d := "ab1cd2ef3gh4ij5kl6mn7op8qr9st0uv1wx2yz3ab4cd5ef6gh7ij8"           // 54 chars (removed k)
	token54e := "mn9op8qr7st6uv5wx4yz3ab2cd1ef0gh9ij8kl7mn6op5qr4st3uv2"           // 54 chars
	token54f := "wx4yz3ab2cd1ef0gh9ij8kl7mn6op5qr4st3uv2wx1yz0ab9cd8ef7"           // 54 chars
	token54g := "gh9ij8kl7mn6op5qr4st3uv2wx1yz0ab9cd8ef7gh6ij5kl4mn3op2"           // 54 chars
	token64 := "abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz01"  // 64 chars (valid max)
	token53 := "abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopq"             // 53 chars (too short)
	token65 := "abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz012" // 65 chars (too long)

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "valid pattern - env file",
			input: `
# .env file
CATTLE_SERVER=https://rancher.example.com
CATTLE_TOKEN=` + token54a + `
`,
			want: []string{token54a},
		},
		{
			name: "valid pattern - rancher_token variable with export",
			input: `
export RANCHER_TOKEN=` + token54b + `
`,
			want: []string{token54b},
		},
		{
			name: "valid pattern - kubernetes yaml",
			input: `
# Kubernetes deployment
env:
  - name: CATTLE_TOKEN
    value: ` + token54c + `
`,
			want: []string{token54c},
		},
		{
			name: "valid pattern - terraform provider",
			input: `
provider "rancher2" {
  api_url   = "https://rancher.example.com"
  token_key = "` + token54d + `"
}
`,
			want: []string{token54d},
		},
		{
			name:  "valid pattern - rancher api token",
			input: `RANCHER_API_TOKEN=` + token54e,
			want:  []string{token54e},
		},
		{
			name:  "valid pattern - cattle bootstrap password",
			input: `CATTLE_BOOTSTRAP_PASSWORD=` + token54f,
			want:  []string{token54f},
		},
		{
			name:  "valid pattern - rancher secret key with quotes",
			input: `RANCHER_SECRET_KEY = "` + token54g + `"`,
			want:  []string{token54g},
		},
		{
			name:  "valid pattern - 60 char token (within 54-64 range)",
			input: `CATTLE_TOKEN=` + token64,
			want:  []string{token64},
		},
		{
			name:  "invalid - too short (53 chars)",
			input: `CATTLE_TOKEN=` + token53,
			want:  nil,
		},
		{
			name:  "invalid - too long (65 chars)",
			input: `CATTLE_TOKEN=` + token65,
			want:  nil,
		},
		{
			name:  "invalid - uppercase chars",
			input: `CATTLE_TOKEN=JSWPL27HS8PD88RMW2MGFGRJTPLJP85FD5V7RHDWR2S6Z22HVT6VJT`,
			want:  nil,
		},
		{
			name: "invalid - no context (should not detect random string)",
			input: `
random_data = "abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuv"
`,
			want: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 && len(test.want) > 0 {
				t.Errorf("keywords '%v' not matched by: %s", d.Keywords(), test.input)
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			if err != nil {
				t.Errorf("error = %v", err)
				return
			}

			if len(results) != len(test.want) {
				t.Errorf("expected %d result(s), got %d", len(test.want), len(results))
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
