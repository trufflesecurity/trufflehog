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
			name: "valid pattern",
			input: `
				[INFO] sending request to the aha.io API
				[DEBUG] using key = 81a1411a7e276fd88819df3137eb406e0f281f8a8c417947ca4b025890c8541c
				[DEBUG] using host = example.aha.io
				[INFO] response received: 200 OK
			`,
			want: []string{"81a1411a7e276fd88819df3137eb406e0f281f8a8c417947ca4b025890c8541cexample.aha.io"},
		},
		{
			name: "valid pattern - key out of prefix range",
			input: `
				[INFO] sending request to the aha.io API
				[WARN] Do not commit the secrets
				[DEBUG] using key = 81a1411a7e276fd88819df3137eb406e0f281f8a8c417947ca4b025890c8541c
				[DEBUG] using host = example.aha.io
				[INFO] response received: 200 OK
			`,
			want: nil,
		},
		{
			name: "valid pattern - only key",
			input: `
				[INFO] sending request to the aha.io API
				[DEBUG] using key = 81a1411a7e276fd88819df3137eb406e0f281f8a8c417947ca4b025890c8541c
				[INFO] response received: 200 OK
			`,
			want: []string{"81a1411a7e276fd88819df3137eb406e0f281f8a8c417947ca4b025890c8541caha.io"},
		},
		{
			name: "valid pattern - only URL",
			input: `
				[INFO] sending request to the example.aha.io API
				[INFO] response received: 200 OK
			`,
			want: nil,
		},
		{
			name: "invalid pattern",
			input: `
				[INFO] sending request to the aha.io API
				[DEBUG] using key = 81a1411a7e276fd88819df3137eJ406e0f281f8a8c417947ca4b025890c8541c
				[DEBUG] using host = 1test.aha.io
				[INFO] response received: 200 OK
			`,
			want: nil,
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
