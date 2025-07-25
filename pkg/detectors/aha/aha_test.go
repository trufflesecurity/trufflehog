package aha

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

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
				[INFO] Sending request to the truffle-security.aha.io API
				[DEBUG] Using Key=b2fb683b321da0f90aa23decc45c74a8578f2eb4390af155d3277e53362a8b45
				[INFO] Response received: 200 OK
			`,
			want: []string{"b2fb683b321da0f90aa23decc45c74a8578f2eb4390af155d3277e53362a8b45"},
		},
		{
			name: "valid pattern",
			input: `
				[DEBUG] Using truffle-security.aha.io domain
				[INFO] Sending request to the API
				[DEBUG] Using Key=b2fb683b321da0f90aa23decc45c74a8578f2eb4390af155d3277e53362a8b45
				[INFO] Response received: 200 OK
			`,
			want: nil,
		},
		{
			name: "valid pattern - only key",
			input: `
				[INFO] Sending request to the aha.io API
				[DEBUG] Using Key=b2fb683b321da0f90aa23decc45c74a8578f2eb4390af155d3277e53362a8b45
				[INFO] Response received: 200 OK
			`,
			want: []string{"b2fb683b321da0f90aa23decc45c74a8578f2eb4390af155d3277e53362a8b45"},
		},
		{
			name: "valid pattern - only URL",
			input: `
				[DEBUG] Using truffle-security.aha.io domain
				[INFO] Sending request to the API
				[INFO] Response received: 200 OK
			`,
			want: nil,
		},
		{
			name: "invalid pattern",
			input: `
				[DEBUG] Using truffle-security.aha.io domain
				[INFO] Sending request to the API
				[DEBUG] Using Key=b2fb683b321da0f90aa23decc4ic74a8578f2eb4390af155d3277e53362a8b45
				[ERROR] Response received: 400 BadRequest
			`,
			want: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 {
				t.Errorf("test %q failed: expected keywords %v to be found in the input", test.name, d.Keywords())
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			require.NoError(t, err)

			if len(results) != len(test.want) {
				t.Errorf("mismatch in result count: expected %d, got %d", len(test.want), len(results))
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
