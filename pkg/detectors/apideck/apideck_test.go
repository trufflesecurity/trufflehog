package apideck

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestApiDeck_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "valid pattern",
			input: `
				[INFO] Sending request to the apideck API
				[DEBUG] Using Key=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
				[DEBUG] Using apideck ID=VfKE9Zh2ZatnqmrloqDu3PCnkNBR6Io4TlSbsG1P
				[INFO] Response received: 200 OK
			`,
			want: []string{
				"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",
			},
		},
		{
			name: "valid pattern - xml",
			input: `
				<com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
  					<scope>GLOBAL</scope>
  					<id>{apideck id J6rYP2lzThxp9JeGg74TDgAXvfQsvzonsHpYHDsG}</id>
  					<secret>{apideck AQAAABAAA sk_live_R5S2B88smT6QfTsUc3o3DedI2hbbcnZwvQKjyudQ41V0T38L8qUDPUTlBDcVE2NwRp1PowPYqnmAHlZ-W1Yr7AWGvpCvT}</secret>
  					<description>configuration for production</description>
					<creationDate>2023-05-18T14:32:10Z</creationDate>
  					<owner>jenkins-admin</owner>
				</com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
			`,
			want: []string{"sk_live_R5S2B88smT6QfTsUc3o3DedI2hbbcnZwvQKjyudQ41V0T38L8qUDPUTlBDcVE2NwRp1PowPYqnmAHlZ-W1Yr7AWGvpCvTJ6rYP2lzThxp9JeGg74TDgAXvfQsvzonsHpYHDsG"},
		},
		{
			name: "invalid pattern",
			input: `
				[INFO] Sending request to the apideck API
				[DEBUG] Using Key=sk_live_GKE08ADdkDV1DQ4vDfaW4ejDHy-TkotfxDmHvQMLX0HRvhtfPwku6olGvsG2vXBg869A0hsOPHHOw48SAF2GO7jBMs6Rt
				[DEBUG] Using apideck ID=VfKE9Zh2ZatnqmrloqDu3PC_kNBR6Io4TlSbsG1P
				[ERROR] Response received: 401 UnAuthorized
			`,
			want: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 {
				t.Errorf("test %q failed: expected keywords %v to be found in the input", test.name, d.Keywords())
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			require.NoError(t, err)

			if len(results) != len(test.want) {
				t.Errorf("mismatch in result count: expected %d, got %d", len(test.want), len(results))
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
