package jumpcloud

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	// JumpCloud API key with jca_ prefix: jca_ + 36 alphanumeric characters (40 total)
	validPattern   = "jca_aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uVwXyZ"
	invalidPattern = "jca_aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uVwXy" // Only 35 chars after prefix
)

func TestJumpcloudV2_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - with jca_ prefix",
			input: fmt.Sprintf("jumpcloud_api_key = '%s'", validPattern),
			want:  []string{validPattern},
		},
		{
			name:  "valid pattern - in config file",
			input: fmt.Sprintf("JUMPCLOUD_API_KEY=%s", validPattern),
			want:  []string{validPattern},
		},
		{
			name:  "valid pattern - multiple occurrences",
			input: fmt.Sprintf("key1 = '%s' key2 = '%s'", validPattern, validPattern),
			want:  []string{validPattern, validPattern},
		},
		{
			name:  "invalid pattern - wrong length",
			input: fmt.Sprintf("api_key = '%s'", invalidPattern),
			want:  []string{},
		},
		{
			name:  "false positive - only digits",
			input: "api_key = 'jca_000000000000000000000000000000000000'",
			want:  []string{},
		},
		{
			name:  "false positive - only lowercase",
			input: "api_key = 'jca_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'",
			want:  []string{},
		},
		{
			name:  "false positive - only uppercase",
			input: "api_key = 'jca_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'",
			want:  []string{},
		},
		{
			name:  "false positive - sequential",
			input: "api_key = 'jca_012345678901234567890123456789012345'",
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
