package rancher

import (
	"context"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validToken   = "jswpl27hs8pd88rmw2mgfgrjtpljp85fd5v7rhdwr2s6z22hvt6vjt"
	invalidToken = "notavalidtoken"
)

func TestRancher_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "env file - CATTLE_TOKEN",
			input: `
CATTLE_SERVER=https://rancher.example.com
CATTLE_TOKEN=` + validToken,
			want: []string{validToken},
		},
		{
			name: "env file - RANCHER_API_TOKEN",
			input: `
RANCHER_API_TOKEN=` + validToken,
			want: []string{validToken},
		},
		{
			name: "quoted value",
			input: `CATTLE_BOOTSTRAP_PASSWORD="` + validToken + `"`,
			want:  []string{validToken},
		},
		{
			name:  "uppercase token - should not detect",
			input: `CATTLE_TOKEN=` + strings.ToUpper(validToken),
			want:  []string{},
		},
		{
			name:  "no context - should not detect",
			input: `random_string=` + validToken,
			want:  []string{},
		},
		{
			name:  "invalid token length",
			input: `CATTLE_TOKEN=` + invalidToken,
			want:  []string{},
		},
		{
			name:  "token too long - should not detect prefix",
			input: `CATTLE_TOKEN=` + validToken + "zzzzzzzzzzzz",
			want:  []string{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(test.want) > 0 && len(matchedDetectors) == 0 {
				t.Errorf("keywords '%v' not matched by: %s", d.Keywords(), test.input)
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			if err != nil {
				t.Errorf("error = %v", err)
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
