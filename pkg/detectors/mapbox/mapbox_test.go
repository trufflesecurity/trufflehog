package mapbox

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validKeyPattern   = "sk.nc7.R5t.P5a.bnM.kvG.s1Q.Gms.RO7.f6q.LMz.YZK.arr.PXw.dmM.Gqt.urp.Oaw.5O8.JCY.grH.x"
	invalidKeyPattern = "sk.nc7.R5t.P5a.bnM.kvG.s1Q.Gms.RO7.f6q.coz.YZK.arr.PXw.dmM.Gqt.urp.Oaw.5O8.JCY.grH.="
	validIdPattern    = "A3xF A3xF A3xF A3xF A3xF A3xF A3xF A3xF A3xF A3xF A3xF"
	invalidIdPattern  = "A3x="
	keyword           = "mapbox"
)

func TestMapBox_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern",
			input: fmt.Sprintf("%s %s %s", keyword, validKeyPattern, validIdPattern),
			want:  []string{validKeyPattern},
		},
		{
			name:  "invalid pattern",
			input: fmt.Sprintf("%s key = '%s' id = '%s'", keyword, invalidKeyPattern, invalidIdPattern),
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
