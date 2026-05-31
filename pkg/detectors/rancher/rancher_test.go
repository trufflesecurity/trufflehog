package rancher

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	// Fake token and server for pattern matching tests only.
	validInput = `
CATTLE_SERVER=https://rancher.example.com
CATTLE_TOKEN=jswpl27hs8pd88rmw2mgfgrjtpljp85fd5v7rhdwr2s6z22hvt6vjt
`
	validToken = "jswpl27hs8pd88rmw2mgfgrjtpljp85fd5v7rhdwr2s6z22hvt6vjt"

	invalidInput = `
# random string without Rancher context
random_data = "abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuv"
`
)

func TestRancher_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid CATTLE_TOKEN pattern",
			input: validInput,
			want:  []string{validToken},
		},
		{
			name:  "no match without cattle/rancher variable name",
			input: invalidInput,
			want:  []string{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(test.want) == 0 {
				if len(matchedDetectors) != 0 {
					t.Errorf("expected no matches, got %d", len(matchedDetectors))
				}
				return
			}
			if len(matchedDetectors) == 0 {
				t.Errorf("keywords '%v' not matched by: %s", d.Keywords(), test.input)
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			if err != nil {
				t.Errorf("error = %v", err)
				return
			}

			got := make([]string, len(results))
			for i, r := range results {
				got[i] = string(r.Raw)
			}

			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
