package appointedd

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
				func validateAppointeddKey() bool {
					appointeddKey := "Ci0a2bSpRyFcZyEXBEr9RHzf3xXllqO=XVoh+t0L0s8T2s3MFntfWhBlovqLaqEadtuJ9=Jy6yCOXmhbpEZPfY7Y"
					log.Println("Checking API key status...")

					if !isActive(appointeddKey) {
						log.Println("API key is inactive or invalid.")
						return false
					}

					log.Println("API key is valid and active.")
					return true
				}`,
			want: []string{"Ci0a2bSpRyFcZyEXBEr9RHzf3xXllqO=XVoh+t0L0s8T2s3MFntfWhBlovqLaqEadtuJ9=Jy6yCOXmhbpEZPfY7Y"},
		},
		{
			name: "valid pattern - xml",
			input: `
				<com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
  					<scope>GLOBAL</scope>
  					<id>{appointedd}</id>
  					<secret>{AQAAABAAA 2pRMKW=JrG9+xYmqlJMa4Omf9goqsSqsM3mIaqG8tG4lwnVrKIslbn=IpLIz7GTDEJUcQ0wlr6B+UjfvSY9XKXwu}</secret>
  					<description>configuration for production</description>
					<creationDate>2023-05-18T14:32:10Z</creationDate>
  					<owner>jenkins-admin</owner>
				</com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
			`,
			want: []string{"2pRMKW=JrG9+xYmqlJMa4Omf9goqsSqsM3mIaqG8tG4lwnVrKIslbn=IpLIz7GTDEJUcQ0wlr6B+UjfvSY9XKXwu"},
		},
		{
			name: "invalid pattern",
			input: `
				func validateAppointeddKey() bool {
					appointeddKey := "Ci0a2bSpRyFcZyEXBEr9RHzf3xXllqO-XVoh+t0L0s8T2s3MFntfWhBlovqLaqEadtuJ9-Jy6yCOXmhbpEZPfY7Y"
					log.Println("Checking API key status...")

					if !isActive(appointeddKey) {
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
