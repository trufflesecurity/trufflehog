package mux

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validKeyPattern      = "87c64847-eda7-a832-6273-8b8b300b29ac"
	invalidKeyPattern    = "G7c64847-eda7-a832-6273-8b8b300b29aG"
	validSecretPattern   = "B8O9w0a7rh0jPxAkfZBhDqb9yppJ4WiiT6yfRR6Fd1eMKL0cAAnv3ShEQU+quVs9xJZgTv0/blh"
	invalidSecretPattern = "B8O9w0a7rh0jPxAkfZBhDqb9yppJ4WiiT6.fRR6Fd1eMKL0cAAnv3ShEQU+quVs9xJZgTv0/blh"
	keyword              = "mux"
)

func TestMux_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - with keyword mux",
			input: fmt.Sprintf("%s '%s' %s ' %s '", keyword, validKeyPattern, keyword, validSecretPattern),
			want:  []string{validKeyPattern + validSecretPattern},
		},
		{
			name:  "valid pattern - key out of prefix range",
			input: fmt.Sprintf("%s keyword is not close to the real key in the data\n = '%s' secret = ' %s '", keyword, validKeyPattern, validSecretPattern),
			want:  []string{},
		},
		{
			name:  "invalid pattern",
			input: fmt.Sprintf("%s key = '%s' secret = ' %s '", keyword, invalidKeyPattern, invalidSecretPattern),
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
