package bitfinex

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestBitFinex_Pattern(t *testing.T) {
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
				func main() {
					bitfinexKey := "HxfuG198amaeCcYkASkto5VuIO-oXcplDV6JZ7OIEQZ"
					bitfinexSecret := "Pf3-3v989gPbJT54D3oDBiFZmJoLpWoTHGvF8xuSBPP"
					http.DefaultClient = client
					c := rest.NewClientWithURL(*api).Credentials(key, secret)
				}
				`,
			want: []string{"HxfuG198amaeCcYkASkto5VuIO-oXcplDV6JZ7OIEQZ", "Pf3-3v989gPbJT54D3oDBiFZmJoLpWoTHGvF8xuSBPP"},
		},
		{
			name: "valid pattern - xml",
			input: `
				<com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
  					<scope>GLOBAL</scope>
  					<id>{bitfinex bdiODwPukXLKUjSLvfeTlKVEwm89zqOhQ2a9chacKcr}</id>
  					<secret>{bitfinex AQAAABAAA MTvK78juiZmddv3eEyoz1gqRwP89OHreiX6fnXkfbce}</secret>
  					<description>configuration for production</description>
					<creationDate>2023-05-18T14:32:10Z</creationDate>
  					<owner>jenkins-admin</owner>
				</com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
			`,
			want: []string{
				"bdiODwPukXLKUjSLvfeTlKVEwm89zqOhQ2a9chacKcr",
				"MTvK78juiZmddv3eEyoz1gqRwP89OHreiX6fnXkfbce",
			},
		},
		{
			name: "invalid pattern",
			input: `
				func main() {
					bitfinexKey := "HxfuG198amaeCcYkASkto5VuIO-oXcplDV6JZ7OIEQZ"
					bitfinexSecret := "kASkto5VuIO%c^HxfuG198amaeCcYkASkto5VuIO"
					http.DefaultClient = client
					c := rest.NewClientWithURL(*api).Credentials(key, secret)
				}
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
