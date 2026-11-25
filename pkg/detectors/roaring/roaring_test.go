package roaring

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validClient   = "-3o_mYkUEBbUKtKjGCg5tgnkzU4T"
	invalidClient = "-3o_mYkUEBbU?tKjGCg5tgnkzU4T"
	validSecret   = "XqTQqnAkyH6We_TEK1CRjhwRV51h"
	invalidSecret = "Xq?QqnAkyH6We_TEK1CRjhwRV51h"
	keyword       = "roaring"
)

func TestRoaring_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - with keyword roaring",
			input: fmt.Sprintf("%s token - '%s'\n%s token - '%s'\n", keyword, validClient, keyword, validSecret),
			want:  []string{validSecret + validSecret},
		},
		{
			name:  "invalid pattern",
			input: fmt.Sprintf("%s token - '%s'\n%s token - '%s'\n", keyword, invalidClient, keyword, invalidSecret),
			want:  []string{},
		},
		{
			name: "pyroaring wheel entries in poetry.lock",
			input: `[[package]]
name = "pyroaring"
version = "1.1.0"
files = [
    {file = "pyroaring-1.1.0-cp310-cp310-manylinux_2_24_aarch64.manylinux_2_28_aarch64.whl", hash = "sha256:55c9d0b708a65308eaa95c53d9de56a2b4425812395f6e57a4d9ad8efb081bf9"},
    {file = "pyroaring-1.1.0-cp311-cp311-macosx_14_0_universal2.whl", hash = "sha256:9cf8608c9d6cb6bff9c624744f7a2ba8ab12276f097a07930490fe0e2219e9be"},
]
`,
			want: []string{},
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
