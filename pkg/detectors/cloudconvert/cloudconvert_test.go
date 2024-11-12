package cloudconvert

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validPattern = `
		# Configuration File: config.yaml
		database:
			host: $DB_HOST
			port: $DB_PORT
			username: $DB_USERNAME
			password: $DB_PASS  # IMPORTANT: Do not share this password publicly

		api:
			auth_type: "Bearer"
			base_url: "https://api.example.com/v1/user"
			cloudconvert_key: "eypn1gEV3BnckI3jcYzUvliSbukvxzO5acvE?ey8VEaR0lmpRa4IXv02fDPnlfdukWtb1/p-nlQlPVGnB52f9KwY4q98aVghXZqoit4AeFxMAHcCytOj61o8lHdcUF9fIcyF2HaFIk/k3Hdt7pS/5rb2eeWcEvc-5XB0T_Oh68AtCG8mOPpwKvzrhhIuEJck3vtFncgbDrSxg5mKkw924rMLP3Tb5tgIRuawZLwBxJL/qVIhAzfDGiIeNTzYOB9zHfHlfw3aZ1i/terePSN5EafVJ1yYw1KRXWL9/kPdAO0yFwSv3mUWx04oIIUURG6QKwO0rk7L0eAxnu4djnSXtqdvH_G50H1SSwwfKUg2Xz25-OZLkhxiaxEMMMY=3x0Yjhs7O1KFkI5gUQKH_VYAU2bJSAqpCKsxaYrdw91wUoya5rflCBVDHjC/BsezIkPFFmEu7sqs3WJg6dZeAiguYx7uZtDx1ILH18f29q9o34bM9SNolZNcG3fN7L2eWjilbmUq/Ty2545WkbHTjlcjLlHPAAjzLebfcFnlMSKH9Tqb/qx3G1z8wfzMa3dn3iRqNHwfmGOmfgK7RjtlZwoVruMjDWEza/o8imZF513yM7FrHTJkTFa1JjVbjU/C85ItZTiJsBUKAt/DbLg6W7lieKgHbgmz3cuwgVR7YDLZJB056TRcU9wrV0SUYDz0gogrpOEnZxdo4fb5UcCllj/AD/dYsfqVSHtTxKWBhun9Iqmx8FjgPtFCFugTxfaaHZ9dUC7TPahdSxixGvnu8EEvAs0Te85eJ9iyeq628Tvboz9J7KMq/uwflJtecSquJiWJT9GsYL5dl3Hr6ZYhxqs1-mrrB5FNzn-NPclPSu9PANtQ1BDuahKy683/t85F8yjug5C5paamNfgiJgOm5Vi/USUmWeVmH_htZoYGJTbOywDkRT1bYp9JIxlWHA29MInhWNrdlxZ_1h-SQ3fM6pzKIoJ0m_T/KXYERPzle0cy_/OnlfIa-yUgBnx_slQ1f9h0AS/PVMv/yZ6W"

		# Notes:
		# - Remember to rotate the secret every 90 days.
		# - The above credentials should only be used in a secure environment.
	`
	secret = "eypn1gEV3BnckI3jcYzUvliSbukvxzO5acvE?ey8VEaR0lmpRa4IXv02fDPnlfdukWtb1/p-nlQlPVGnB52f9KwY4q98aVghXZqoit4AeFxMAHcCytOj61o8lHdcUF9fIcyF2HaFIk/k3Hdt7pS/5rb2eeWcEvc-5XB0T_Oh68AtCG8mOPpwKvzrhhIuEJck3vtFncgbDrSxg5mKkw924rMLP3Tb5tgIRuawZLwBxJL/qVIhAzfDGiIeNTzYOB9zHfHlfw3aZ1i/terePSN5EafVJ1yYw1KRXWL9/kPdAO0yFwSv3mUWx04oIIUURG6QKwO0rk7L0eAxnu4djnSXtqdvH_G50H1SSwwfKUg2Xz25-OZLkhxiaxEMMMY=3x0Yjhs7O1KFkI5gUQKH_VYAU2bJSAqpCKsxaYrdw91wUoya5rflCBVDHjC/BsezIkPFFmEu7sqs3WJg6dZeAiguYx7uZtDx1ILH18f29q9o34bM9SNolZNcG3fN7L2eWjilbmUq/Ty2545WkbHTjlcjLlHPAAjzLebfcFnlMSKH9Tqb/qx3G1z8wfzMa3dn3iRqNHwfmGOmfgK7RjtlZwoVruMjDWEza/o8imZF513yM7FrHTJkTFa1JjVbjU/C85ItZTiJsBUKAt/DbLg6W7lieKgHbgmz3cuwgVR7YDLZJB056TRcU9wrV0SUYDz0gogrpOEnZxdo4fb5UcCllj/AD/dYsfqVSHtTxKWBhun9Iqmx8FjgPtFCFugTxfaaHZ9dUC7TPahdSxixGvnu8EEvAs0Te85eJ9iyeq628Tvboz9J7KMq/uwflJtecSquJiWJT9GsYL5dl3Hr6ZYhxqs1-mrrB5FNzn-NPclPSu9PANtQ1BDuahKy683/t85F8yjug5C5paamNfgiJgOm5Vi/USUmWeVmH_htZoYGJTbOywDkRT1bYp9JIxlWHA29MInhWNrdlxZ_1h-SQ3fM6pzKIoJ0m_T/KXYERPzle0cy_/OnlfIa-yUgBnx_slQ1f9h0AS/PVMv/yZ6W"
)

func TestCloudConvert_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern",
			input: validPattern,
			want:  []string{secret},
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
