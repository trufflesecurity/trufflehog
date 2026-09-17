package metabase

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validKeyPattern   = "Y49ftoUer6aYZOzdkRzlENnW8PHnD9zf9dP9"
	invalidKeyPattern = "=49ftoUer6aYZOzdkRzlENnW8PHnD9zf9dP9"
	// slugFP is a 36-char URL slug (lowercase words separated by hyphens) that
	// was falsely reported as a Metabase session token because the old pattern
	// allowed hyphens. See issue #4633.
	slugFP                = "-journal-deduplication-id-to-voucher"
	validBaseUrlPattern   = "https://tiwRdoa.metabase.com"
	invalidBaseUrlPattern = "https://tiwRdo^.metabase.com"
	keyword               = "metabase"
)

func TestMetabase_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - with keyword metabase",
			input: fmt.Sprintf("%s '%s' %s '%s'", keyword, validKeyPattern, keyword, validBaseUrlPattern),
			want:  []string{validKeyPattern + validBaseUrlPattern},
		},
		{
			name:  "valid pattern - key out of prefix range",
			input: fmt.Sprintf("%s keyword is not close to the real key in the data\n = '%s' '%s'", keyword, validKeyPattern, validBaseUrlPattern),
			want:  []string{},
		},
		{
			name:  "invalid pattern",
			input: fmt.Sprintf("%s key = '%s' url = '%s'", keyword, invalidKeyPattern, invalidBaseUrlPattern),
			want:  []string{},
		},
		{
			name:  "false positive - URL slug with hyphens is not a session token",
			input: fmt.Sprintf("metabase query - https://metabase.example.com/question/12345%s?partition_key=202501", slugFP),
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
