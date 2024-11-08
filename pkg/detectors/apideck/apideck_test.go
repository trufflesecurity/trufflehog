package apideck

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
	validKeyPattern = "sk_live_abc123def456ghi789jklmno123456pqrstuvwxyz-1234567890123456789012345678901234567890AAui09pU8as"
	validIdPattern  = "apideck_id: 1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t"
	invalidPattern  = strings.ReplaceAll(validKeyPattern, "sk_live", "sk_inactive") + strings.ReplaceAll(validIdPattern, "1", "$")
)

func TestApiDeck_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern",
			input: fmt.Sprintf("credentials: %s \n %s", validKeyPattern, validIdPattern),
			want: []string{
				validKeyPattern + "1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t",
			},
		},
		{
			name:  "invalid pattern",
			input: fmt.Sprintf("credentials: %s", invalidPattern),
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
