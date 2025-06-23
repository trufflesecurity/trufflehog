package instamojo

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validKeyPattern      = "ZrGOAl9jlTlAKxw4hXZXeRmd6wvndEr2pX0fqDv2"
	invalidKeyPattern    = "VdZVfhpWN0O0FL0KKZauMMtgJytUPAmkNRO9Vwq"
	validSecretPattern   = "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0u1V2w3X4y5Z6a7B8c9D0e1F2g3H4i5J6k7L8m9N0o1P2q3R4s5T6u7V8w9X0y1Z2a3B4c5D6e7F8g9H0D2e3F4g5"
	invalidSecretPattern = "V2w3X4y5Z6a7!8c9D0e1F2g3H4i5J6k7L8m9N0o@P2q3R4s5T6u7V8w9X0y1Z2a3_4c5D6e7F8g9H0i1J2k3L4m5-6o7P8q9R0s1T2u3V4w5X6y7Z8a9B0c1D2e3F4+="
	keyword              = "instamojo"
)

func TestInstamojo_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - with keyword instamojo",
			input: fmt.Sprintf("%s '%s' %s '%s'", keyword, validKeyPattern, keyword, validSecretPattern),
			want:  []string{"ZrGOAl9jlTlAKxw4hXZXeRmd6wvndEr2pX0fqDv2"},
		},
		{
			name:  "valid pattern - key out of prefix range",
			input: fmt.Sprintf("%s keyword is not close to the real key in the data\n = '%s' secret = '%s'", keyword, validKeyPattern, validSecretPattern),
			want:  []string{},
		},
		{
			name:  "invalid pattern",
			input: fmt.Sprintf("%s key = '%s' secret = '%s'", keyword, invalidKeyPattern, invalidSecretPattern),
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
