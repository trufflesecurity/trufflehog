package salesforce

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
    validAccessToken   = "00MMW9rRmrlVvBi!gZTTPUfk_nkghR_01qsw3NdcHTeDF8dQKWJmiOcfSjfdymrqXH0_vMci6VmxHzrlw07JSfeyMJrA_N89fUJU9vrAYWn_isTE"
    invalidAccessToken = "00MMW9rRmrlVvBi!gZTTPUfk_nkghR_01qsw3NdcHTeDF8dQKWJmiOcf?jfdymrqXH0_vMci6VmxHzrlw07JSfeyMJrA_N89fUJU9vrAYWn_isTE"
    validInstance      = "https://wDIMT.HmGz15hePYJBiaiG4leH6y.my.salesforce.com"
    invalidInstance    = "https://wDIMT.HmGz15hePYJBi?iG4leH6y.my.salesforce.com"
    keyword            = "salesforce"
)

func TestSalesforce_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - with keyword salesforce",
			input: fmt.Sprintf("%s token - '%s'\n%s token - '%s'\n", keyword, validAccessToken, keyword, validInstance),
			want:  []string{validAccessToken},
		},
		{
			name:  "invalid pattern",
			input: fmt.Sprintf("%s token - '%s'\n%s token - '%s'\n", keyword, invalidAccessToken, keyword, invalidInstance),
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
					t.Errorf("expected %d results, only received %d", len(test.want), len(results))
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
