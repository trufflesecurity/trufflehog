package captaindata

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestCaptainData_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "typical pattern",
			input: "captaindata_project = '12345678-1234-1234-1234-123456789012' captaindata_api_key = '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef'",
			want:  []string{"12345678-1234-1234-1234-1234567890121234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"},
		},
		{
			name: "finds all matches",
			input: `captaindata_project1 = '12345678-1234-1234-1234-123456789012' captaindata_api_key1 = '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef'
captaindata_project2 = '87654321-4321-4321-4321-210987654321' captaindata_api_key2 = 'fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321'`,
			want: []string{
				"12345678-1234-1234-1234-1234567890121234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
				"12345678-1234-1234-1234-123456789012fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321",
				"87654321-4321-4321-4321-210987654321fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321",
				"87654321-4321-4321-4321-2109876543211234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			},
		},
		{
			name:  "invalid pattern",
			input: "captaindata_project = '123456' captaindata_api_key = '1234567890'",
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
