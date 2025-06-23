package tallyfy

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validPattern   = "K6azzL9elP7qKOQIyU2PF68Ej1WiZWCIQBUY.nYqWoaP99FfEwzxQOuMLbkFvyu4i4AM74Dk55iokNXhD2YeyFuwze060X8NNXN1WqiVgavVLTuL9S45Q8hpa5yB9rVREeWrR3YhNclTRKL1vnW1f4BJZIMIOIPNFtN70ZXwIZEdDXzvZZtBLFA36R1WlKKKKd1NV7Rnc1RLCk9trhYwFsngcRFVPvqwLbPIv3hsfia31IDFDHXAdHuWXyDb0dA0vvOQqxmYn0kUEX13rEdFzBnZ7rJL861B9vCYkbBJSgujp.EV15KF8CXF3GmQ5NgXo_8KMkmLc55Z6v3JBVstk381Bpr53q3tqISdfjj3zNj1bRFk6KXNrjUzLMkZjVBbpme5-dAkJFcs5r1jmHXkrRmE0xLk25TUX8TukVdzCjWxYogQJopcXHfw_uqpF8JJ1FomLhpRu8Ag0RrRaO-IfF0Nz-SbQcIOtEJrvbfzVF3LVDPU5ID8bi3cz3qVuS30TxR-0fLaQHnRq0POGYlsy-OEZI078Wj0g3diAr8Yy6SGOkT-CB0p175aYkhUmNGhWpsGMyjASr-MXT9i2HPUPoI50X-Xw6HsQrqydLqYQg-uA2FDTpqza3IZMcyYj-4AeFWgzj3fSgyqM-IK47Cf52hzrW4YPmI9Lz-ooGPbd1ZAJXVLDrNtsG9U4VetIxPKpz4RgeVnGwy2NW53U1L7sMixwewhBvL8WL-T5FEyLt8-q-6h_ubaOxhVKjEzwIkunAzLYfCLYCj0MaPvTfn2mSbJ5r_5Mc6Mx-skqUt_yJhKsyYoXQOFni0awoPIf_xOEpvjmUELr2ZyPB-EqiFXB9zRC4oYO2QULWQYocd0cCKHsRL_ulfZ9qI1XR4Wl04DumNuJHdXodiSWXMwUOgsNf-vMs-2IHoVahWkihTSV6FyDNAitSLSEGNK5x_egOOY5tJWyvZpU8s80Rw7lF6Y-8C5f"
	invalidPattern = "K?azzL9elP7qKOQIyU2PF68Ej1WiZWCIQBUY.nYqWoaP99FfEwzxQOuMLbkFvyu4i4AM74Dk55iokNXhD2YeyFuwze060X8NNXN1WqiVgavVLTuL9S45Q8hpa5yB9rVREeWrR3YhNclTRKL1vnW1f4BJZIMIOIPNFtN70ZXwIZEdDXzvZZtBLFA36R1WlKKKKd1NV7Rnc1RLCk9trhYwFsngcRFVPvqwLbPIv3hsfia31IDFDHXAdHuWXyDb0dA0vvOQqxmYn0kUEX13rEdFzBnZ7rJL861B9vCYkbBJSgujp.EV15KF8CXF3GmQ5NgXo_8KMkmLc55Z6v3JBVstk381Bpr53q3tqISdfjj3zNj1bRFk6KXNrjUzLMkZjVBbpme5-dAkJFcs5r1jmHXkrRmE0xLk25TUX8TukVdzCjWxYogQJopcXHfw_uqpF8JJ1FomLhpRu8Ag0RrRaO-IfF0Nz-SbQcIOtEJrvbfzVF3LVDPU5ID8bi3cz3qVuS30TxR-0fLaQHnRq0POGYlsy-OEZI078Wj0g3diAr8Yy6SGOkT-CB0p175aYkhUmNGhWpsGMyjASr-MXT9i2HPUPoI50X-Xw6HsQrqydLqYQg-uA2FDTpqza3IZMcyYj-4AeFWgzj3fSgyqM-IK47Cf52hzrW4YPmI9Lz-ooGPbd1ZAJXVLDrNtsG9U4VetIxPKpz4RgeVnGwy2NW53U1L7sMixwewhBvL8WL-T5FEyLt8-q-6h_ubaOxhVKjEzwIkunAzLYfCLYCj0MaPvTfn2mSbJ5r_5Mc6Mx-skqUt_yJhKsyYoXQOFni0awoPIf_xOEpvjmUELr2ZyPB-EqiFXB9zRC4oYO2QULWQYocd0cCKHsRL_ulfZ9qI1XR4Wl04DumNuJHdXodiSWXMwUOgsNf-vMs-2IHoVahWkihTSV6FyDNAitSLSEGNK5x_egOOY5tJWyvZpU8s80Rw7lF6Y-8C5f"
	keyword        = "tallyfy"
)

func TestTallyfy_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - with keyword tallyfy",
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
