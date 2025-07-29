package repositorykey

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestAzureAPIManagementRepositoryKey_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: `valid pattern`,
			input: `
				AZURE_URL=https://test.scm.azure-api.net
				PASSWORD=git&202503251200&R2xlVEmqi+OW130dxWIDhfw1K6XKw/gxc5P9te3cwWBtnK2XkZq5k+VUAdnuX1Y0T/I5CRK9fJyBJr31SmFEYw==
			`,
			want: []string{"test.scm.azure-api.netgit&202503251200&R2xlVEmqi+OW130dxWIDhfw1K6XKw/gxc5P9te3cwWBtnK2XkZq5k+VUAdnuX1Y0T/I5CRK9fJyBJr31SmFEYw=="},
		},
		{
			name: `invalid host pattern`,
			input: `
				AZURE_URL=https://test.scm.azure.net
				PASSWORD=git&202503251200&R2xlVEmqi+OW130dxWIDhfw1K6XKw/gxc5P9te3cwWBtnK2XkZq5k+VUAdnuX1Y0T/I5CRK9fJyBJr31SmFEYw==
			`,
			want: []string{},
		},
		{
			name: `invalid password pattern without ==`,
			input: `
				AZURE_URL=https://test.scm.azure-api.net
				PASSWORD=git&202503251200&R2xlVEmqi+OW130dxWIDhfw1K6XKw/gxc5P9te3cwWBtnK2XkZq5k+VUAdnuX1Y0T/I5CRK9fJyBJr31SmFEYw=
			`,
			want: []string{},
		},
		{
			name: `invalid password pattern with wrong expiry date`,
			input: `
				AZURE_URL=https://test.scm.azure-api.net
				PASSWORD=git&20250325&R2xlVEmqi+OW130dxWIDhfw1K6XKw/gxc5P9te3cwWBtnK2XkZq5k+VUAdnuX1Y0T/I5CRK9fJyBJr31SmFEYw==
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
