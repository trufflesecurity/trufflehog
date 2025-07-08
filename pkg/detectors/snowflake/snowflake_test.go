package snowflake

import (
	"context"
	"fmt"
	"testing"

	"github.com/brianvoe/gofakeit/v7"
	"github.com/google/go-cmp/cmp"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestSnowflake_Pattern(t *testing.T) {

	validAccount := "tuacoip-zt74995"
	validPrivateLinkAccount := "tuacoip-zt74995.privatelink"
	validSingleCharacterAccount := "tuacoip-z"
	validUsername := gofakeit.Username()
	invalidUsername := "Spencer@5091.com" // special characters not allowed

	validPassword := common.GenerateRandomPassword(true, true, true, false, 10)
	invalidPassword := "!12" // invalid length

	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  [][]string
	}{
		{
			name:  "Snowflake Credentials",
			input: fmt.Sprintf("snowflake: \n account=%s \n username=%s \n password=%s \n database=SNOWFLAKE", validAccount, validUsername, validPassword),
			want: [][]string{
				{validAccount, validUsername, validPassword},
			},
		},
		{
			name:  "Private Snowflake Credentials",
			input: fmt.Sprintf("snowflake: \n account=%s \n username=%s \n password=%s \n database=SNOWFLAKE", validPrivateLinkAccount, validUsername, validPassword),
			want: [][]string{
				{validPrivateLinkAccount, validUsername, validPassword},
			},
		},
		{
			name:  "Snowflake Credentials - Single Character account",
			input: fmt.Sprintf("snowflake: \n account=%s \n username=%s \n password=%s \n database=SNOWFLAKE", validSingleCharacterAccount, validUsername, validPassword),
			want: [][]string{
				{validSingleCharacterAccount, validUsername, validPassword},
			},
		},
		{
			name:  "Snowflake Credentials - Invalid Username & Password",
			input: fmt.Sprintf("snowflake: \n account=%s \n username=%s \n password=%s \n database=SNOWFLAKE", validAccount, invalidUsername, invalidPassword),
			want:  [][]string{},
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
