package plaidkey

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validSecret   = "6e611cb89c263457b5e028d66c16c4"
	invalidSecret = "3vl81ihtozf9im7dqz7ldp6kxbsd8y"
	validId       = "60e3ee4019a2660010f8bc54"
	invalidId     = "ic1Ah5b49ycvmz2vgvlgxtb0"
	validToken    = "access-sandbox-833d862e-ffa8-43a7-ae28-72f56f1acb32"
	invalidToken  = "access-sandbox-g33z362e-fha8-43a7-au28-7kf56z1acl32"
	keyword       = "plaid"
)

func TestPlaidKey_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - with keyword plaid",
			input: fmt.Sprintf("%s secret - '%s'\n%s client id - '%s'\n%s token - '%s'", keyword, validSecret, keyword, validId, keyword, validToken),
			want:  []string{fmt.Sprintf("%s:%s:%s", validSecret, validId, validToken)},
		},
		{
			name:  "invalid pattern - with keyword plaid",
			input: fmt.Sprintf("%s secret - '%s'\n%s client id - '%s'\n%s token - '%s'", keyword, invalidSecret, keyword, invalidId, keyword, invalidToken),
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
