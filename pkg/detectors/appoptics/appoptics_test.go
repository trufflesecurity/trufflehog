package appoptics

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestAppOptics_Pattern(t *testing.T) {
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
				func validateAppOpticsKey() bool {
					appopticsKey := "Xwl4ViaAFDLrAmFX9g1blkUVC5dJj2he3a1tzkpJ4-PznQukQruRjqMFbEG73L92LJyBGMZ"
					log.Println("Checking API key status...")

					if !isActive(appopticsKey) {
						log.Println("API key is inactive or invalid.")
						return false
					}

					log.Println("API key is valid and active.")
					return true
				}`,
			want: []string{"Xwl4ViaAFDLrAmFX9g1blkUVC5dJj2he3a1tzkpJ4-PznQukQruRjqMFbEG73L92LJyBGMZ"},
		},
		{
			name: "valid pattern - xml",
			input: `
				<com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
  					<scope>GLOBAL</scope>
  					<id>{appoptics}</id>
  					<secret>{AQAAABAAA zxsb8yzT0RbIJ1TAalB87LOVUcT1b4uEgvT4tXCcSqv_gcmlrx5aQRleHPDFKePjpHFof5J}</secret>
  					<description>configuration for production</description>
					<creationDate>2023-05-18T14:32:10Z</creationDate>
  					<owner>jenkins-admin</owner>
				</com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
			`,
			want: []string{"zxsb8yzT0RbIJ1TAalB87LOVUcT1b4uEgvT4tXCcSqv_gcmlrx5aQRleHPDFKePjpHFof5J"},
		},
		{
			name: "invalid pattern",
			input: `
				func validateAppOpticsKey() bool {
					appopticsKey := "Xwl4ViaAFDLrAmFX9g1blkUVC5dJj2h:3a1tzkpJ43PznQukQruRjqMFbEG73L92LJyBGMZ"
					log.Println("Checking API key status...")

					if !isActive(appopticsKey) {
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
