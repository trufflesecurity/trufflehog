package easyinsight

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validKeyPattern = "987ahjjdasgUcaaraAdd"
	validIDPattern  = "poiuy76RaEf90ertgh0K"
	// this should result in 4 combinations
	complexPattern = `easyinsight credentials
						these credentials are for testing a pattern
						key: A876AcaraTsaAKcae09a
						id: chECk12345ChecK12345
						-------------------------
						second credentials:
						key: B874CDaraTsaAKVBe08A
						id: CHECK12345ChecK09876`
	invalidPattern = "poiuy76=a_$90ertgh0K"
)

func TestEasyInsight_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern",
			input: fmt.Sprintf("easyinsight key = '%s' easy-insight id = '%s", validKeyPattern, validIDPattern),
			want:  []string{validKeyPattern + validIDPattern, validIDPattern + validKeyPattern},
		},
		{
			name:  "valid pattern - complex",
			input: fmt.Sprintf("easyinsight token = '%s'", complexPattern),
			want: []string{
				"A876AcaraTsaAKcae09achECk12345ChecK12345",
				"A876AcaraTsaAKcae09aCHECK12345ChecK09876",
				"B874CDaraTsaAKVBe08ACHECK12345ChecK09876",
				"B874CDaraTsaAKVBe08AchECk12345ChecK12345",
			},
		},
		{
			name:  "valid pattern - out of prefix range",
			input: fmt.Sprintf("easyinsight key and id keyword is not close to the real token = '%s|%s'", validKeyPattern, validIDPattern),
			want:  nil,
		},
		{
			name:  "invalid pattern",
			input: fmt.Sprintf("easyinsight = '%s|%s'", invalidPattern, invalidPattern),
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
