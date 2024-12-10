package snowflake

import (
	"context"
	"fmt"
	"testing"

	"github.com/brianvoe/gofakeit/v7"
	"github.com/google/go-cmp/cmp"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestSnowflake_Pattern(t *testing.T) {
	username := gofakeit.Username()
	password := gofakeit.Password(true, true, true, false, false, 10)

	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  [][]string
	}{
		{
			name:  "Snowflake Credentials",
			input: fmt.Sprintf("snowflake: \n account=%s \n username=%s \n password=%s \n database=SNOWFLAKE", "tuacoip-zt74995", username, password),
			want: [][]string{
				[]string{"tuacoip-zt74995", username, password},
			},
		},
		{
			name:  "Private Snowflake Credentials",
			input: fmt.Sprintf("snowflake: \n account=%s \n username=%s \n password=%s \n database=SNOWFLAKE", "tuacoip-zt74995.privatelink", username, password),
			want: [][]string{
				[]string{"tuacoip-zt74995.privatelink", username, password},
			},
		},

		{
			name:  "Snowflake Credentials - Single Character account",
			input: fmt.Sprintf("snowflake: \n account=%s \n username=%s \n password=%s \n database=SNOWFLAKE", "tuacoip-z", username, password),
			want: [][]string{
				[]string{"tuacoip-z", username, password},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			detectorMatches := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(detectorMatches) == 0 {
				t.Errorf("keywords '%v' not matched by: %s", d.Keywords(), test.input)
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			if err != nil {
				t.Errorf("error = %v", err)
				return
			}

			resultsArray := make([][]string, len(results))
			for i, r := range results {
				resultsArray[i] = []string{r.ExtraData["account"], r.ExtraData["username"], string(r.Raw)}
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
				actual[r.ExtraData["account"]] = struct{}{}
				actual[r.ExtraData["username"]] = struct{}{}
			}
			expected := make(map[string]struct{}, len(test.want))
			for _, v := range test.want {
				for _, value := range v {
					expected[value] = struct{}{}
				}
			}

			if diff := cmp.Diff(expected, actual); diff != "" {
				t.Errorf("%s diff: (-want +got)\n%s", test.name, diff)
			}
		})
	}
}
