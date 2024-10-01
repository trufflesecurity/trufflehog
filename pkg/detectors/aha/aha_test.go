package aha

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestAha_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern",
			input: "aha.io = '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff/example.aha.io'",
			want:  []string{"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"},
		},
		{
			name:  "valid pattern - detect URL far away from keyword",
			input: "aha.io = '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n URL is not close to the keyword but should be detected example.aha.io'",
			want:  []string{"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"},
		},
		{
			name:  "valid pattern - key out of prefix range",
			input: "aha.io keyword is not close to the real key and secret = '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff/example.aha.io'",
			want:  nil,
		},
		{
			name:  "valid pattern - only key",
			input: "aha.io 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
			want:  []string{"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"},
		},
		{
			name:  "valid pattern - only URL",
			input: "aha.io example.aha.io",
			want:  nil,
		},
		{
			name:  "invalid pattern",
			input: "aha.io 00112233445566778899aabbCC$%eeff00112233445566778899aabbccddeeff/example.fake.io",
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
