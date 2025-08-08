package accuweather

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestAccuWeather_Pattern(t *testing.T) {
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
				[INFO] Sending request to accuweather API
				[DEBUG] Using API_KEY=Qh6DP6Zf7vHtmnDDsbS219qcz4d883Y9
				[INFO] Response received: 200 OK
			`,
			want: []string{"Qh6DP6Zf7vHtmnDDsbS219qcz4d883Y9"},
		},
		{
			name: "valid pattern - xml",
			input: `
				<com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
  					<scope>GLOBAL</scope>
  					<id>{accuweather}</id>
  					<secret>{accuweather AQAAABAAA BJDD9bYh8bR586Wcw3F1lvkUYy3RZZbD}</secret>
  					<description>configuration for production</description>
					<creationDate>2023-05-18T14:32:10Z</creationDate>
  					<owner>jenkins-admin</owner>
				</com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
			`,
			want: []string{"BJDD9bYh8bR586Wcw3F1lvkUYy3RZZbD"},
		},
		{
			name: "valid pattern - out of prefix range",
			input: `
				[INFO] Sending request to accuweather API
				[INFO] Processing request
				[Info] Response received: 200 OK
				[DEBUG] Used API_KEY=Qh6DP6Zf7vHtmnDDsbS219qcz4d883Y9
			`,
			want: nil,
		},
		{
			name: "invalid pattern",
			input: `
				[INFO] Sending request to accuweather API
				[DEBUG] Using API_KEY=Qh6DP6Zf7vHtm@DDsbS219qcz4d883Y9
				[ERROR] Response received: 400 BadRequest
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
