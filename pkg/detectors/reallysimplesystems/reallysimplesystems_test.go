package reallysimplesystems

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validPattern   = "eyt_8-ytglklqvyjGF6dgbXsCSMRLdryUWQCSQ1n1uSph1Ppl.jMeMx0EkxVLcmbKPTi7kPYKzNa04V96eiJlV.XxtKFDKTJCkcThvKR2x0ctVUL.FrbHVXEx55VZZPD0FKW4onNDO05Ab_9cbnrLTr4d--.eyX.hZw.Q5g-pvyWS5jjDUyiE60WZSgQq4uM8PUVw1-OJegMnGGLEKq48G5X7zgQAcYvUIRQy4Ku.gKQkNFIL4Nlj3ob7Bi4VUDs_DjvtS_Jxho-Hn_hgIhfYQVw19wQCcc8m7v2jCXz2MTi74vpzW7aY2C123i5uFr1KdVQLX.Xlf5ZtuLAsYZ5MsG1G6VYO_t7l6nl8D-Y3fml7uSGPXkeQT7AW1HKOTrBdGj0L_OMMYBaZ4-R9tnUjM7Jf1LExVn2NIQnNGR7Jyl69WigxQGLaUbNvE9DQkVtV4ar0FORi8mrwAQdb5UxZkOxW4me_F189Y-rs0h9q4vrjmM3Fu1Uj_UCrV4IP6AYr4b9yXzgAlcybQSNUISltLwYC.07LKjRy.dLvF-A2b5mIjyKbR3rOUmiXfeAveBRakkEOKSNOSTDVM839O9a-8tqAggj8eDdPunO8Pg6L_Af_eJowZNhtRluVuFDTHuUW.lAG1bqm.ZJQak800cspbDbB8InwOb0V1UvoO.c.ZOAWM3fQVoidNeDbKbWKR3JdE3iWCGsqz89Zdd6LkxwHAd5TRLn.ZVg67d1.g2S3kadXrTZ0qN6o_7apQ38PbGKydnCTLMfdgN6uIPqAtQntsF6YNvNfFHnXgsfhTkVUDJc5g6oQB_jDeGa8rkCmH6_DO6Z1qV04G.fj.QLJIgMhcdGL8Y3NMRv87spZxNWmX1glZ1AYQlWbbqwzAC1v-p0ImXQSuq6G8aIt8e4w7FnOmOn_Q0NwD85JRgdy.W4f.5hX-zLhj1RDqvC1-Ebd2OLDdne0xqMMNe4kGnzQ6dpDtbZXPcim443CyFxaFD_DK5-Iupc032AKV_Sm9eDSlRuAmAQ7LhvypNWi_6e9NuVUEQ5P6HfBe1eXkZ3y5HkZpWbJqJW2D"
	invalidPattern = "ayt_8-ytglklqvyjGF6dgbXsCSMRLdryUWQCSQ1n1uSph1Ppl.jMeMx0EkxVLcmbKPTi7kPYKzNa04V96eiJlV.XxtKFDKTJCkcThvKR2x0ctVUL.FrbHVXEx55VZZPD0FKW4onNDO05Ab_9cbnrLTr4d--.eyX.hZw.Q5g-pvyWS5jjDUyiE60WZSgQq4uM8PUVw1-OJegMnGGLEKq48G5X7zgQAcYvUIRQy4Ku.gKQkNFIL4Nlj3ob7Bi4VUDs_DjvtS_Jxho-Hn_hgIhfYQVw19wQCcc8m7v2jCXz2MTi74vpzW7aY2C123i5uFr1KdVQLX.Xlf5ZtuLAsYZ5MsG1G6VYO_t7l6nl8D-Y3fml7uSGPXkeQT7AW1HKOTrBdGj0L_OMMYBaZ4-R9tnUjM7Jf1LExVn2NIQnNGR7Jyl69WigxQGLaUbNvE9DQkVtV4ar0FORi8mrwAQdb5UxZkOxW4me_F189Y-rs0h9q4vrjmM3Fu1Uj_UCrV4IP6AYr4b9yXzgAlcybQSNUISltLwYC.07LKjRy.dLvF-A2b5mIjyKbR3rOUmiXfeAveBRakkEOKSNOSTDVM839O9a-8tqAggj8eDdPunO8Pg6L_Af_eJowZNhtRluVuFDTHuUW.lAG1bqm.ZJQak800cspbDbB8InwOb0V1UvoO.c.ZOAWM3fQVoidNeDbKbWKR3JdE3iWCGsqz89Zdd6LkxwHAd5TRLn.ZVg67d1.g2S3kadXrTZ0qN6o_7apQ38PbGKydnCTLMfdgN6uIPqAtQntsF6YNvNfFHnXgsfhTkVUDJc5g6oQB_jDeGa8rkCmH6_DO6Z1qV04G.fj.QLJIgMhcdGL8Y3NMRv87spZxNWmX1glZ1AYQlWbbqwzAC1v-p0ImXQSuq6G8aIt8e4w7FnOmOn_Q0NwD85JRgdy.W4f.5hX-zLhj1RDqvC1-Ebd2OLDdne0xqMMNe4kGnzQ6dpDtbZXPcim443CyFxaFD_DK5-Iupc032AKV_Sm9eDSlRuAmAQ7LhvypNWi_6e9NuVUEQ5P6HfBe1eXkZ3y5HkZpWbJqJW2D"
	keyword        = "reallysimplesystems"
)

func TestReallySimpleSystems_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - with keyword reallysimplesystems",
			input: fmt.Sprintf("%s token = '%s'", keyword, validPattern),
			want:  []string{validPattern},
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
