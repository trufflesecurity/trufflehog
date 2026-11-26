package daytona

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestDaytona_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	key := "dtn_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "typical pattern",
			input: "DAYTONA_API_KEY=" + key,
			want:  []string{key},
		},
		{
			name:  "duplicate is deduplicated",
			input: key + " " + key,
			want:  []string{key},
		},
		{
			name:  "too short",
			input: "dtn_0123456789abcdef",
			want:  nil,
		},
		{
			name:  "uppercase hex not matched",
			input: "dtn_0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef",
			want:  nil,
		},
		{
			name:  "too long",
			input: key + "0",
			want:  nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			detectorMatches := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(detectorMatches) == 0 {
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
				actual[string(r.Raw)] = struct{}{}
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
