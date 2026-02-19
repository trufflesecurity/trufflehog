package artifactory

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestArtifactory_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name             string
		input            string
		want             []string
	}{
        {
			name: "valid pattern - single valid basic auth uri",
			input: `
				[INFO] Sending request to the artifactory API
				[DEBUG] Some log line here
				https://user123:ATBB123abcDEF456ghiJKL789mnoPQR@test.jfrog.io/artifactory/api/pypi/pypi/simple
				[INFO] Response received: 200 OK
			`,
			want: []string{
				"user123:ATBB123abcDEF456ghiJKL789mnoPQR@test.jfrog.io",
			},
		},
        {
			name: "valid pattern - single valid basic auth uri with no http prefix",
			input: `
				[INFO] artifactory request to https://test.jfrog.io/artifactory/api/ping
				simpleuser123:ATBB123abcDEF456ghiJKL789mnoPQR@test.jfrog.io/artifactory/api/pypi/pypi/simple
			`,
			want: []string{
				"simpleuser123:ATBB123abcDEF456ghiJKL789mnoPQR@test.jfrog.io",
			},
		},
        {
			name: "valid pattern - single valid basic auth uri with postfix",
			input: `
				https://user123:ATBB123abcDEF456ghiJKL789mnoPQR@test.jfrog.io?x=1
				[INFO] Response received: 200 OK
			`,
			want: []string{
				"user123:ATBB123abcDEF456ghiJKL789mnoPQR@test.jfrog.io",
			},
		},
		{
			name: "valid pattern - multiple basic auth uris with duplicates",
			input: `
				[INFO] artifactory logs
				https://user123:token123@test.jfrog.io/artifactory/api/foo
				https://user123:token123@test.jfrog.io/artifactory/api/foo  # duplicate
				http://another:secret456@rwxtOp.jfrog.io/artifactory/api/bar
			`,
			want: []string{
				"user123:token123@test.jfrog.io",
				"another:secret456@rwxtOp.jfrog.io",
			},
		},
		{
			name: "invalid pattern - invalid host (not jfrog.io)",
			input: `
				[INFO] Sending request to the artifactory API
				https://user123:token123@example.com/artifactory/api/ping
			`,
			want: nil,
		},
		{
			name: "invalid pattern - missing password",
			input: `
				[INFO] Sending request to the artifactory API
				http://user123:@test.jfrog.io/artifactory/api/ping
			`,
			want: nil,
		},
		{
			name: "invalid pattern - no basic auth uri present",
			input: `
				[INFO] artifactory request to https://test.jfrog.io/artifactory/api/ping
				[DEBUG] Using header Authorization: Bearer sometoken
			`,
			want: nil,
		},
        {
			name: "invalid pattern - one character subdomain",
			input: `
				[INFO] artifactory logs
				https://user123:token123@a.jfrog.io/artifactory/api/foo
			`,
			want: nil,
		},
        {
			name: "invalid pattern - domain starts with -",
			input: `
				[INFO] artifactory logs
				https://user123:token123@-test.jfrog.io/artifactory/api/foo
			`,
			want: nil,
		},
        {
			name: "invalid pattern - domain ends with -",
			input: `
				[INFO] artifactory logs
				https://user123:token123@test-.jfrog.io/artifactory/api/foo
			`,
			want: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Ensure the Aho-Corasick prefilter is triggered for positive cases.
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(test.want) > 0 && len(matchedDetectors) == 0 {
				t.Errorf("expected detector to be triggered for input containing Artifactory/jfrog keywords")
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			require.NoError(t, err)

			if len(test.want) == 0 {
				if len(results) != 0 {
					t.Errorf("expected no results, got %d", len(results))
				}
				return
			}

			if len(results) != len(test.want) {
				t.Errorf("mismatch in result count: expected %d, got %d", len(test.want), len(results))
			}

			actual := make(map[string]struct{}, len(results))
			for _, r := range results {
				// Prefer RawV2 (sanitized username:password@host) if present.
				val := string(r.RawV2)
				if val == "" {
					val = string(r.Raw)
				}
				actual[val] = struct{}{}
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
