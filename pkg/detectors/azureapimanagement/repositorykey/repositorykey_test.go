package repositorykey

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validPattern = `
		AZURE_URL=https://test.scm.azure-api.net
		PASSWORD=git&202503251200&R2xlVEmqi+OW130dxWIDhfw1K6XKw/gxc5P9te3cwWBtnK2XkZq5k+VUAdnuX1Y0T/I5CRK9fJyBJr31SmFEYw==
	`
	invalidHostPattern = `
		AZURE_URL=https://test.scm.azure.net
		PASSWORD=git&202503251200&R2xlVEmqi+OW130dxWIDhfw1K6XKw/gxc5P9te3cwWBtnK2XkZq5k+VUAdnuX1Y0T/I5CRK9fJyBJr31SmFEYw==
	`
	invalidPasswordPattern1 = `
		AZURE_URL=https://test.scm.azure-api.net
		PASSWORD=git&202503251200&R2xlVEmqi+OW130dxWIDhfw1K6XKw/gxc5P9te3cwWBtnK2XkZq5k+VUAdnuX1Y0T/I5CRK9fJyBJr31SmFEYw=
	`
	invalidPasswordPattern2 = `
		AZURE_URL=https://test.scm.azure-api.net
		PASSWORD=git&20250325&R2xlVEmqi+OW130dxWIDhfw1K6XKw/gxc5P9te3cwWBtnK2XkZq5k+VUAdnuX1Y0T/I5CRK9fJyBJr31SmFEYw==
	`
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
			name:  `valid pattern`,
			input: validPattern,
			want:  []string{"test.scm.azure-api.net" + "git&202503251200&R2xlVEmqi+OW130dxWIDhfw1K6XKw/gxc5P9te3cwWBtnK2XkZq5k+VUAdnuX1Y0T/I5CRK9fJyBJr31SmFEYw=="},
		},
		{
			name:  `invalid host pattern`,
			input: invalidHostPattern,
			want:  []string{},
		},
		{
			name:  `invalid password pattern without ==`,
			input: invalidPasswordPattern1,
			want:  []string{},
		},
		{
			name:  `invalid password pattern with wrong expiry date`,
			input: invalidPasswordPattern2,
			want:  []string{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 {
				t.Errorf("keywords '%v' not matched by: %s", d.Keywords(), test.input)
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			if err != nil {
				t.Errorf("error = %v", err)
				return
			}

			if len(results) != len(test.want) {
				if len(results) == 0 {
					t.Errorf("did not receive result")
				} else {
					if diff := cmp.Diff(test.want, results); diff != "" {
						t.Errorf("%s expected %d results, received %d: (-want +got)\n%s", test.name, len(test.want), len(results), diff)
					}
				}
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
