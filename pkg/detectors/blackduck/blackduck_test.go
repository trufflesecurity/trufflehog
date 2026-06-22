package blackduck

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	// base64("a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d:f0e1d2c3-b4a5-4968-8778-695a4b3c2d1e")
	validToken = "YTFiMmMzZDQtZTVmNi00YTdiLThjOWQtMGUxZjJhM2I0YzVkOmYwZTFkMmMzLWI0YTUtNDk2OC04Nzc4LTY5NWE0YjNjMmQxZQ=="
	// Correct length/alphabet, but decodes to plain text instead of "<uuid>:<uuid>".
	invalidToken  = "dGhpcy1pcy1ub3QtYS1yZWFsLWJsYWNrZHVjay10b2tlbi1qdXN0LWZpbGxlci1jb250ZW50LXBhZGRpbmcteHl6MDEyMzQ1Ng=="
	validEndpoint = "https://blackduck.example.com"
	keyword       = "blackduck"
)

func TestBlackduck_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - token and url",
			input: fmt.Sprintf("%s api token - '%s'\n%s url - '%s'\n", keyword, validToken, keyword, validEndpoint),
			want:  []string{validToken + validEndpoint},
		},
		{
			name:  "invalid pattern - token does not decode to <uuid>:<uuid>",
			input: fmt.Sprintf("%s api token - '%s'\n%s url - '%s'\n", keyword, invalidToken, keyword, validEndpoint),
			want:  []string{},
		},
		{
			name:  "no result without an endpoint - verification needs the server url",
			input: fmt.Sprintf("%s api token - '%s'\n", keyword, validToken),
			want:  []string{},
		},
		{
			// Underscore form only, and a host with no "blackduck" substring, so
			// the chunk matches solely on the "black_duck" keyword.
			name:  "valid pattern - black_duck underscore form (env-var style)",
			input: fmt.Sprintf("BLACK_DUCK_API_TOKEN='%s'\nBLACK_DUCK_URL='https://bd.example.com'\n", validToken),
			want:  []string{validToken + "https://bd.example.com"},
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
