package cloudflareglobalapikey

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validV2Pattern = "cfk_ZE4CrcFhEIDXk9vL2sTLeARsFp2ZZYbydVDhhIUq8573bbfe / testuser1005@example.com"
)

func TestCloudFlareGlobalAPIKeyV2_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid v2 pattern - no keyword proximity needed",
			input: fmt.Sprintf("some config: %s", validV2Pattern),
			want:  []string{"cfk_ZE4CrcFhEIDXk9vL2sTLeARsFp2ZZYbydVDhhIUq8573bbfetestuser1005@example.com"},
		},
		{
			name:  "valid v2 pattern - no email nearby still emits result",
			input: "API_KEY=cfk_ZE4CrcFhEIDXk9vL2sTLeARsFp2ZZYbydVDhhIUq8573bbfe",
			want:  []string{"cfk_ZE4CrcFhEIDXk9vL2sTLeARsFp2ZZYbydVDhhIUq8573bbfe"},
		},
		{
			name:  "no match for legacy format",
			input: "cfk_: abcdef1234567890abcdef1234567890abcdef0 / testuser1005@example.com",
			want:  nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 && test.want != nil {
				t.Errorf("keywords '%v' not matched by: %s", d.Keywords(), test.input)
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			if err != nil {
				t.Errorf("error = %v", err)
				return
			}

			if len(results) != len(test.want) {
				t.Errorf("expected %d results, got %d", len(test.want), len(results))
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
