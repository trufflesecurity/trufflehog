package simplynoted

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validPattern   = "NSPwR0>Q,wTEJcGyFF)bvY#FACMwu9DzLFD|bLC@D2d1-zILY&sPo6N_AhOwD(:N0`Td[NL2dZt;>yzn3yN'5x[ia&0v2&M0D_r0!L3#dt:Mx^IdcL{xSBIlyQ4jd*=4U2=gdr%2ZDvQqxGaX1WAnoZy2Ny20rnl^f8P/Y.u`jxsOy%2iesTS&u|7SMQ]wJ*f2c?lQ:o4&X(/[y.ZK%2Av100u($ZeTU2N4yCFgKp5PqicqSkgjIla31uGS0OvpmpSiy@rFvthHA,k&)uRAM6$>#dt:Mx^IdcL{xSBIlyQ4jd*=4U2=gdr%2ZDvQqxGJcGyFF)bvY#FACMwu9DzL"
	invalidPattern = "N PwR0>Q,wTEJcGyFF)bvY#FACMwu9DzLFD|bLC@D2d1-zILY&sPo6N_AhOwD(:N0`Td[NL2dZt;>yzn3yN'5x[ia&0v2&M0D_r0!L3#dt:Mx^IdcL{xSBIlyQ4jd*=4U2=gdr%2ZDvQqxGaX1WAnoZy2Ny20rnl^f8P/Y.u`jxsOy%2iesTS&u|7SMQ]wJ*f2c?lQ:o4&X(/[y.ZK%2Av100u($ZeTU2N4yCFgKp5PqicqSkgjIla31uGS0OvpmpSiy@rFvthHA,k&)uRAM6$>#dt:Mx^IdcL{xSBIlyQ4jd*=4U2=gdr%2ZDvQqxGJcGyFF)bvY#FACMwu9DzL"
	keyword        = "simplynoted"
)

func TestSimplyNoted_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - with keyword simplynoted",
			input: fmt.Sprintf("%s token = '%s'", keyword, validPattern),
			want:  []string{validPattern},
		},
		{
			name:  "valid pattern - ignore duplicate",
			input: fmt.Sprintf("%s token = '%s' | '%s'", keyword, validPattern, validPattern),
			want:  []string{validPattern},
		},
		{
			name:  "valid pattern - key out of prefix range",
			input: fmt.Sprintf("%s keyword is not close to the real key in the data\n = '%s'", keyword, validPattern),
			want:  []string{},
		},
		{
			name:  "invalid pattern",
			input: fmt.Sprintf("%s = '%s'", keyword, invalidPattern),
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
