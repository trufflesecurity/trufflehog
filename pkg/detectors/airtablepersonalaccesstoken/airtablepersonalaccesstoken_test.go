package airtablepersonalaccesstoken

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestAirtablepersonalaccesstoken_Pattern(t *testing.T) {
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
				[INFO] Sending request to the airtable API
				[DEBUG] Using Key=patfqpIZBPU6EAt5x.458546d9c77b21f8a98141f2a4039d5626010f19efc16c20d57c4f41d44c8c85
				[INFO] Response received: 200 OK
			`,
			want: []string{"patfqpIZBPU6EAt5x.458546d9c77b21f8a98141f2a4039d5626010f19efc16c20d57c4f41d44c8c85"},
		},
		{
			name: "valid pattern - xml",
			input: `
				<com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
  					<scope>GLOBAL</scope>
  					<id>{airtable}</id>
  					<secret>{airtable AQAAABAAA pat2kATFGrujqJTbT.e2082656c470902d83b47dc804e693df1deb30161affbda39d879a2cf44bef13}</secret>
  					<description>configuration for production</description>
					<creationDate>2023-05-18T14:32:10Z</creationDate>
  					<owner>jenkins-admin</owner>
				</com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
			`,
			want: []string{"pat2kATFGrujqJTbT.e2082656c470902d83b47dc804e693df1deb30161affbda39d879a2cf44bef13"},
		},
		{
			name: "finds all matches",
			input: `
				[INFO] Sending request to the API
				[DEBUG] Using airtable Key=patfqpIZBPU6EAt5x.458546d9c77b21f8a98141f2a4039d5626010f19efc16c20d57c4f41d44c8c85
				[ERROR] Response received: 401 UnAuthorized
				[DEBUG] Using airtable Key=pat0VXr5I2HcapZE8.da2606afb7d97e936719ec952a4a18b44045e385d4ddf4f38dcc246fb63f0165
				[INFO] Response received: 200 OK
			`,
			want: []string{
				"patfqpIZBPU6EAt5x.458546d9c77b21f8a98141f2a4039d5626010f19efc16c20d57c4f41d44c8c85",
				"pat0VXr5I2HcapZE8.da2606afb7d97e936719ec952a4a18b44045e385d4ddf4f38dcc246fb63f0165",
			},
		},
		{
			name: "invalid pattern",
			input: `
				[INFO] Sending request to the airtable API
				[DEBUG] Using Key=patfqpIZBPU6EAt5xe.458546d9c77b21f8a98141f2a403-d5626010f19efc16c20d57c4f41d44c8c85
				[ERROR] Response received: 401 UnAuthorized
			`,
			want: []string{},
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
