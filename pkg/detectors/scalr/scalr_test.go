package scalr

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validKey   = "bmy2Q33nZnlwZ5wCu_umGbBHF_6547oPzvAGLpUEwhWwOJmU5DUlZIOWZ0Yr7g2Yt4s3ZyyfWxzOlLLOmkGXpzuQ3.gEhgGUHUngyyiPIZjVoYQ.W0O8k4G3JBC705AXkXxANwrF"
	invalidKey = "bmy2Q33nZnlwZ5wCu?umGbBHF?6547oPzvAGLpUEwhWwOJmU5DUlZIOWZ0Yr7g2Yt4s3ZyyfWxzOlLLOmkGXpzuQ3?gEhgGUHUngyyiPIZjVoYQ.W0O8k4G3JBC705AXkXxANwrF"
	validId    = "h7bcggvlzhq6t5m47f37jav"
	invalidId  = "?7bcgg?lzhq6t5m47f37jav"
	keyword    = "scalr"
)

func TestScalr_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - with keyword scalr",
			input: fmt.Sprintf("%s token - '%s'\n%s token - '%s'\n", keyword, validKey, keyword, validId),
			want:  []string{validKey, validKey},
		},
		{
			name:  "invalid pattern",
			input: fmt.Sprintf("%s token - '%s'\n%s token - '%s'\n", keyword, invalidKey, keyword, invalidId),
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
