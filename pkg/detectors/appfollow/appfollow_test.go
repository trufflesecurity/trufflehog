package appfollow

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validPattern   = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.333HbjEo1oxVUFcASR0sQ8cMuIJRLcMd5H9iJWDbovCw6ESjNtuoEMQQGPN9aSoxponxrTPvn1.btADhgNetsaUBuwoyHo5ip0Jab6N6MEBnSaT6CHiO6z"
	invalidPattern = "eyQ0eXAiOiJMM1QiLDJhbGciOiJIUXI1NiK7.abcdefgh1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcd1234efgh5678ijkl9012.qwerty12345-ASDFG67890_zxcvb_ABCDE"
)

func TestAppFollow_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern",
			input: fmt.Sprintf("appfollow credential: %s", validPattern),
			want:  []string{"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.333HbjEo1oxVUFcASR0sQ8cMuIJRLcMd5H9iJWDbovCw6ESjNtuoEMQQGPN9aSoxponxrTPvn1.btADhgNetsaUBuwoyHo5ip0Jab6N6MEBnSaT6CHiO6z"},
		},
		{
			name:  "invalid pattern",
			input: fmt.Sprintf("appfollow credential: %s", invalidPattern),
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
