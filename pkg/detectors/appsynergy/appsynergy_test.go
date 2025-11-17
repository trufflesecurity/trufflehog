package appsynergy

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestAppSynergy_Pattern(t *testing.T) {
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
				func validateAppSynergyKey() bool {
					appSyneregyKey := "mg1pgwlndtq7rbk8i3kum344aso8ggp02ximdhsp8nsqasd3btxf84lz9ekfdpwo"
					log.Println("Checking API key status...")

					if !isActive(appSyneregyKey) {
						log.Println("API key is inactive or invalid.")
						return false
					}

					log.Println("API key is valid and active.")
					return true
				}`,
			want: []string{"mg1pgwlndtq7rbk8i3kum344aso8ggp02ximdhsp8nsqasd3btxf84lz9ekfdpwo"},
		},
		{
			name: "valid pattern - xml",
			input: `
				<com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
  					<scope>GLOBAL</scope>
  					<id>{appsynergy}</id>
  					<secret>{AQAAABAAA ri1vn9m2otlg3yi8wwjegltc1t3bi4ljogg6c80onnrox2t9fuim6tce430fhklz}</secret>
  					<description>configuration for production</description>
					<creationDate>2023-05-18T14:32:10Z</creationDate>
  					<owner>jenkins-admin</owner>
				</com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
			`,
			want: []string{"ri1vn9m2otlg3yi8wwjegltc1t3bi4ljogg6c80onnrox2t9fuim6tce430fhklz"},
		},
		{
			name: "invalid pattern",
			input: `
				func validateAppSynergyKey() bool {
					appSyneregyKey := "mg1pgwlndtq7rbk8i3kum_44aso8ggp02ximdhsp8nsqasd3btxf84lz9ekfdpwo"
					log.Println("Checking API key status...")

					if !isActive(appSyneregyKey) {
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
