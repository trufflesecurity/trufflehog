package asanapersonalaccesstoken

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	// Old format token
	validPatternOld = "asana_token: 594776654034514343561917591881414702593902454625364993/1724908107002616220416212965:Yv3DoiSFhtsgUwN3AcnXWjK8zabQHKSHBRHpuNKVjz3oCcpyDIdXRm3GL4SUDkTMFoTbRDCHe8tTBHxdtoXItn"
	// New format token with two forward slashes
	newValidPattern  = "asana_token: 7/9823746598123746/8923746598123456:7f1a3c9be84d2a6c4e7d9c32bf1e7f88"
	invalidPattern   = "asana_token: 1724908107002616220416212965%594776654034514343561917591881414702593902454625364993:Yv3DoiSFhtsgUwN3AcnXWjK8zabQHKSHBRHpuNKVjz3oCcpyDIdXRm3GL4SUDkTMFoTbRDCHe8tTBHxdtoXItn-ij2gwtg/xn9vh4jvsokdfaic0bn"
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
			name:  "valid pattern - old format",
			input: validPatternOld,
			want:  []string{"594776654034514343561917591881414702593902454625364993/1724908107002616220416212965:Yv3DoiSFhtsgUwN3AcnXWjK8zabQHKSHBRHpuNKVjz3oCcpyDIdXRm3GL4SUDkTMFoTbRDCHe8tTBHxdtoXItn"},
		},
		{
			name:  "valid pattern - new format",
			input: newValidPattern,
			want:  []string{"7/9823746598123746/8923746598123456:7f1a3c9be84d2a6c4e7d9c32bf1e7f88"},
		},
		{
			name:  "invalid pattern",
			input: invalidPattern,
			want:  nil,
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
