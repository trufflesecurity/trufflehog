package appfollow

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
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
			name: "valid pattern",
			input: `
				func validateAppFollowKey() bool {
					key := "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.hdMLjiIayyb5cgbcVtjKywQwqeNKnsxZEhnJnX6wzhnblpmpjF4c2mbdmVVylTayE6M8ZE3h4V.fmnUM4cjvbe1JMFDuBSwWNEYQFHrD5AEm6p2Ir9w7K6"

					// isActive check if the key is active or not
					return isActive(key)
				}`,
			want: []string{"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.hdMLjiIayyb5cgbcVtjKywQwqeNKnsxZEhnJnX6wzhnblpmpjF4c2mbdmVVylTayE6M8ZE3h4V.fmnUM4cjvbe1JMFDuBSwWNEYQFHrD5AEm6p2Ir9w7K6"},
		},
		{
			name: "valid pattern - xml",
			input: `
				<com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
  					<scope>GLOBAL</scope>
  					<id>{appfollow}</id>
  					<secret>{AQAAABAAA eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.YwK6gJ8sMVylaDNuXRiGFLRR1kgZaLF45EbJ0qHSRaW4CRtWaqWciTZZXxkk4a4wLh8f7cTTlb.wvTVCRC1RLCpd98q4WK3ef6M3TBrb08AkS9-jNOdA_r}</secret>
  					<description>configuration for production</description>
					<creationDate>2023-05-18T14:32:10Z</creationDate>
  					<owner>jenkins-admin</owner>
				</com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
			`,
			want: []string{"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.YwK6gJ8sMVylaDNuXRiGFLRR1kgZaLF45EbJ0qHSRaW4CRtWaqWciTZZXxkk4a4wLh8f7cTTlb.wvTVCRC1RLCpd98q4WK3ef6M3TBrb08AkS9-jNOdA_r"},
		},
		{
			name: "invalid pattern",
			input: `
				func validateAppFollowKey() bool {
					apiKey := "eyJ0eXAiOiJKV1QiLCJhbGCiOiJIUzI1NiJ9.hdMLjiIayyb5cgbcVtjKywQwqeNKnsxZEhnJnX6wzhnblpmpjF4c2mbdVylTayE6M8ZE3h4V.fmnUM4cjvbe1JMFDuBSwWNEYQFHrDEm6p2Ir9w7K6"
					log.Println("Checking API key status...")

					if !isActive(apiKey) {
						log.Println("API key is inactive or invalid.")
						return false
					}

					log.Println("API key is valid and active.")
					return true
				}`,
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
