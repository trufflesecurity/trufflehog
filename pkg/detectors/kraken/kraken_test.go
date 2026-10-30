package kraken

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validKeyPattern             = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkq"
	invalidKeyPattern           = "AQIDBAUGBwgJCgsMDQ4PEBESExQV=hcYGRobHB0eHyAhIiMkJSYnKCkq"
	validPrivKeyPattern         = "KywtLi8wMTIzNDU2Nzg5Ojs8PT4/QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl9gYWJjZGVmZ2hpag=="
	validUnpaddedPrivKeyPattern = "KywtLi8wMTIzNDU2Nzg5Ojs8PT4/QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl9gYWJjZGVmZ2hpag"
	invalidPrivKeyPattern       = "KywtLi8wMTIzNDU2Nzg5Ojs8PT4/QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl9gYWJjZG=mhpag=="
	keyword                     = "kraken"
)

func TestKraken_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - with keyword kraken",
			input: fmt.Sprintf("%s '%s' %s '%s'", keyword, validKeyPattern, keyword, validPrivKeyPattern),
			want:  []string{validKeyPattern + validPrivKeyPattern},
		},
		{
			name:  "valid pattern - private key without base64 padding",
			input: fmt.Sprintf("%s '%s' %s '%s'", keyword, validKeyPattern, keyword, validUnpaddedPrivKeyPattern),
			want:  []string{validKeyPattern + validUnpaddedPrivKeyPattern},
		},
		{
			name: "valid pattern - quoted env vars",
			input: fmt.Sprintf(`
KRAKEN_API_KEY="%s"
KRAKEN_PRIVATE_KEY="%s"
`, validKeyPattern, validPrivKeyPattern),
			want: []string{validKeyPattern + validPrivKeyPattern},
		},
		{
			name:  "valid pattern - key out of prefix range",
			input: fmt.Sprintf("%s keyword is not close to the real key in the data\n key = '%s' domain: '%s'", keyword, validKeyPattern, validPrivKeyPattern),
			want:  []string{},
		},
		{
			name:  "invalid pattern - malformed api key base64 padding",
			input: fmt.Sprintf("%s key = '%s' %s secret = '%s'", keyword, invalidKeyPattern, keyword, validPrivKeyPattern),
			want:  []string{},
		},
		{
			name:  "invalid pattern - malformed private key base64 padding",
			input: fmt.Sprintf("%s key = '%s' %s secret = '%s'", keyword, validKeyPattern, keyword, invalidPrivKeyPattern),
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
