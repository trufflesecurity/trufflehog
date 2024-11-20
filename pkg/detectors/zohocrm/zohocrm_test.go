package zohocrm

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validPattern   = "1000.1fa6966eafbb115624baa4103269e50e.e57d155232227b4e41fa7dd2b88dd4d4"
	invalidPattern = "1000.24baa4103269e50e.41fa7dd2b88dd4d4"
)

func TestZohocrm_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "typical pattern - with keyword zoho crm",
			input: fmt.Sprintf("zoho crm token = '%s'", validPattern),
			want:  []string{"1000.1fa6966eafbb115624baa4103269e50e.e57d155232227b4e41fa7dd2b88dd4d4"},
		},
		{
			name:  "typical pattern - ignore duplicate",
			input: fmt.Sprintf("zoho crm token = '%s' | '%s'", validPattern, validPattern),
			want:  []string{"1000.1fa6966eafbb115624baa4103269e50e.e57d155232227b4e41fa7dd2b88dd4d4"},
		},
		{
			name:  "invalid pattern",
			input: fmt.Sprintf("zoho crm = '%s'", invalidPattern),
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
