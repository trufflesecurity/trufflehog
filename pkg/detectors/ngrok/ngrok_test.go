package ngrok

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validPattern    = "2WIRSIHOQyHSVklZnoz2k6bTYdH_0E7z0Ta9QEyR1fZvQ0KU9"
	validPatternAlt = "3GuTI5JXfaLtYILkc6N0xopP2V0_89zkDfefiuMv6Hk1z6oYi"
	// Authtokens exist in the wild with letter-leading and 20-char suffixes
	// (confirmed live against the ngrok API), so both must be detected.
	validPatternLetterSuffix = "3GuTI5JXfaLtYILkc6N0xopP2V0_a9zkDfefiuMv6Hk1z6oYi"
	validPatternShortSuffix  = "4HvUJ6KYgbMuZJMld7O1yqqQ3W1_b8ylEgfgjvNw7Il2z7pZ"
	invalidPattern           = "2WIRSIHOQyHSVklZnoz2k6bT?dH_0E7z0Ta9QEyR1fZvQ0KU9"
	invalidIDPattern         = "ak_3GuTI5JXfaLtYILkc6N0xopP2V0"
	keyword                  = "ngrok"
)

func TestNgrok_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - with keyword ngrok",
			input: fmt.Sprintf("%s token = '%s'", keyword, validPattern),
			want:  []string{"2WIRSIHOQyHSVklZnoz2k6bTYdH_0E7z0Ta9QEyR1fZvQ0KU9"},
		},
		{
			name:  "valid pattern - api key not starting with 2",
			input: fmt.Sprintf("%s token = '%s'", keyword, validPatternAlt),
			want:  []string{validPatternAlt},
		},
		{
			name:  "valid pattern - ignore duplicate",
			input: fmt.Sprintf("%s token = '%s' | '%s'", keyword, validPattern, validPattern),
			want:  []string{"2WIRSIHOQyHSVklZnoz2k6bTYdH_0E7z0Ta9QEyR1fZvQ0KU9"},
		},
		{
			name:  "valid pattern - authtoken suffix not starting with digit",
			input: fmt.Sprintf("%s token = '%s'", keyword, validPatternLetterSuffix),
			want:  []string{validPatternLetterSuffix},
		},
		{
			name:  "valid pattern - authtoken with 20 char suffix",
			input: fmt.Sprintf("%s token = '%s'", keyword, validPatternShortSuffix),
			want:  []string{validPatternShortSuffix},
		},
		{
			name:  "valid pattern - key out of prefix range",
			input: fmt.Sprintf("%s keyword is not close to the real key in the data\n = '%s'", keyword, validPattern),
			want:  []string{},
		},
		{
			name:  "invalid pattern",
			input: fmt.Sprintf("%s = '%s'", keyword, invalidPattern),
			want:  []string{},
		},
		{
			name:  "invalid pattern - api key resource id not bearer token",
			input: fmt.Sprintf("%s api_key = '%s'", keyword, invalidIDPattern),
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
