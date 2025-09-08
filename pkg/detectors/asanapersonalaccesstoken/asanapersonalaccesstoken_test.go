package asanapersonalaccesstoken

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestAsanaPersonalAccessToken_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "valid pattern - old format",
			input: `
				[INFO] Sending request to the asana API
				[DEBUG] Using Old Format asana Key=5947/1724908107002616220416212965:Yv3DoiSFhtsgUwN3AcnXWjK8zabQHKSHBRHpuNKVjz3oCcpyDIdXRm3GL4SUDkTMFoTb
				[ERROR] Response received: 400 BadRequest
				[DEBUG] Using new format asana Key=7/9823746598123746/8923746598123456:7f1a3c9be84d2a6c4e7d9c32bf1e7f88
				[INFO] Response received: 200 OK
			`,
			want: []string{
				"5947/1724908107002616220416212965:Yv3DoiSFhtsgUwN3AcnXWjK8zabQHKSHBRHpuNKVjz3oCcpyDIdXRm3GL4SUDkTMFoTb",
				"7/9823746598123746/8923746598123456:7f1a3c9be84d2a6c4e7d9c32bf1e7f88",
			},
		},
		{
			name: "valid pattern - xml",
			input: `
				<com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
  					<scope>GLOBAL</scope>
  					<id>{asana}</id>
  					<secret>{AQAAABAAA 891435852083139681602524390768273271357927849104481/366163755073364840345913922341185329292536814045275090976491644844014597476863956806652784056747/17480879147700616278211801017829125:Hb7meGPLBz7jH7e1fiHetN355omiO9Zt8fewjSOX4qfUoWDzvvlNA6lBx9rNuR8EAEElmtmmL9J4ilO8m2D56n}</secret>
  					<description>configuration for production</description>
					<creationDate>2023-05-18T14:32:10Z</creationDate>
  					<owner>jenkins-admin</owner>
				</com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
			`,
			want: []string{"891435852083139681602524390768273271357927849104481/366163755073364840345913922341185329292536814045275090976491644844014597476863956806652784056747/17480879147700616278211801017829125:Hb7meGPLBz7jH7e1fiHetN355omiO9Zt8fewjSOX4qfUoWDzvvlNA6lBx9rNuR8EAEElmtmmL9J4ilO8m2D56n"},
		},
		{
			name: "invalid pattern",
			input: `
				[INFO] Sending request to the asana API
				[DEBUG] Using Old Format asana Key=5947766540345/172490810700261:Yv3DoiSFhjK8zabQHKSHBRHpuNKVjz3oCcpyDIdXRm3GL4SUDkTMFoTbRDCHe8tTBHxdtoXItn
				[ERROR] Response received: 400 BadRequest
				[DEBUG] Using new format asana Key=7/98237465/8923746598156:7f1a3c9be84d2a6c4e7d9c32bf1e7f88
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
