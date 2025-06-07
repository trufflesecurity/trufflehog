package aha

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validPattern   = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff/example.aha.io"
	invalidPattern = "00112233445566778899aabbCC$%eeff00112233445566778899aabbccddeeff/example.fake.io"
)

func TestAha_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	key := strings.Split(validPattern, "/")[0]
	url := strings.Split(validPattern, "/")[1]

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern",
			input: fmt.Sprintf("aha.io = '%s'", validPattern),
			want:  []string{key},
		},
		{
			name:  "valid pattern - detect URL far away from keyword",
			input: fmt.Sprintf("aha.io = '%s\n URL is not close to the keyword but should be detected %s'", key, url),
			want:  []string{key},
		},
		{
			name:  "valid pattern - key out of prefix range",
			input: fmt.Sprintf("aha.io keyword is not close to the real key and secret = '%s'", validPattern),
			want:  nil,
		},
		{
			name:  "valid pattern - only key",
			input: fmt.Sprintf("aha.io %s", key),
			want:  []string{key},
		},
		{
			name:  "valid pattern - only URL",
			input: fmt.Sprintf("aha.io %s", url),
			want:  nil,
		},
		{
			name:  "invalid pattern",
			input: fmt.Sprintf("aha.io %s", invalidPattern),
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
