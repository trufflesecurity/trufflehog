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
	validDigitOrgAccount := "ABC1234-EXAMPLE"                   // org segment contains digits; missed by the old [a-zA-Z]{7} pattern
	validRegionQualifiedAccount := "xy12345-prod.us-east-1"     // region/cloud suffix contains dots; truncated by the old account body
	fullHostAccount := "tuacoip-zt74995.snowflakecomputing.com" // account stored as the full login host
	fullHostAccountIdentifier := "tuacoip-zt74995"              // verifyMatch re-appends the suffix, so it must be reported stripped
	validUsername := gofakeit.Username()
	specialCharUsername := "super!user@corp" // '!' and '@' are valid Snowflake login-name characters

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
			name:  "Snowflake Credentials - Account with digits in org segment",
			input: fmt.Sprintf("snowflake: \n account=%s \n username=%s \n password=%s \n database=SNOWFLAKE", validDigitOrgAccount, validUsername, validPassword),
			want: [][]string{
				{validDigitOrgAccount, validUsername, validPassword},
			},
		},
		{
			name:  "Snowflake Credentials - Region-qualified account",
			input: fmt.Sprintf("snowflake: \n account=%s \n username=%s \n password=%s \n database=SNOWFLAKE", validRegionQualifiedAccount, validUsername, validPassword),
			want: [][]string{
				{validRegionQualifiedAccount, validUsername, validPassword},
			},
		},
		{
			name:  "Snowflake Credentials - Account stored as full host",
			input: fmt.Sprintf("snowflake: \n account=%s \n username=%s \n password=%s \n database=SNOWFLAKE", fullHostAccount, validUsername, validPassword),
			want: [][]string{
				{fullHostAccountIdentifier, validUsername, validPassword},
			},
		},
		{
			name:  "Snowflake Credentials - Username with ! and @",
			input: fmt.Sprintf("snowflake: \n account=%s \n username=%s \n password=%s \n database=SNOWFLAKE", validAccount, specialCharUsername, validPassword),
			want: [][]string{
				{validAccount, specialCharUsername, validPassword},
			},
		},
		{
			// The password `!12` is below the minimum capture length, so no
			// credential is emitted. `UsernameRegexCheck` is a deliberately broad
			// pre-filter (it can cross-match neighbouring fields), so rejection
			// here is driven by the password, not the username; the name reflects
			// that rather than claiming username validation.
			name:  "Snowflake Credentials - Password too short is rejected",
			input: fmt.Sprintf("snowflake: \n account=%s \n username=%s \n password=%s \n database=SNOWFLAKE", validAccount, validUsername, invalidPassword),
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
