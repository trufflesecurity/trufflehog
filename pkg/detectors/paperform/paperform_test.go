package paperform

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validPattern   = "NvBbE5vYVPhidc-tiZ7E6DvP.z4bAQj29KEZOCv_XEl1pIn.Y1q8JoeGNoSelGj.db1iQpLM0fsype86LD.Vk.p6yweF5A2MlfxXDrEd7nz2SBExnTpp4QRN94pBAeulPLLtzqTz--y_UuF1g6cjE_.kuW_u5He0QkBdLMkyAgSx94N3Csj9LY37XOmUp9IIi9LXpTvZGa8oywp6JuMfhzwg5OCEvdp9mx.UyfQcnnJtYzzP5dItmwfEC-KJIvjvS8LF2NU2w2japQHtnAJqBAn3_EP-FN78wHnDEWANANT0cfor6kDqyKraO0Y-26PdB6xBjm3_VpU.8hnKIyoKdLQ6S.HZwr5rx0Bx76zXTCBv4uEzhtDFcDqVPN8ZG_kE90P..ldReG0jU4w3YA2jbaOgi6i-8llYWGoCiFFBm3Od-zLOEDYL2BlGsUFRUkiEMjytCVDqcIOdfPT7GQcd3wdmort6FFv8SbCu95f2gBCcM.5.ZmMxIOybubMGmiRunYM8-pSaVvXfBQSkM2Eygh15tkKCDHf8X3InAkPh7HQn13mP5y1gFRLsVAUWb-91PeHASP6hluUEdsX3uLQ9OJFenKrk.0zS9Goy08bfttd4h4Jtb2JV8vbJ8-3Wb4AJWqf0eUALMxOChB3sSBKW37s4vDb1NKOnoqOeoYQUBijqRGu9YLKIAimwo7Uvl0CuD7bWNrERweBqNVWjfGhlE8Yvvklm5YhCk5XY02pOa3IjMf_TDKhbTr8bh_20SXevnDk80XKg_3mWbhuieL23kx835AokAg9JpEkgydBBqo8nzQg23R5xJzKRT64kgb5GBlzuM9Oxh7pXsmzlYf"
	invalidPattern = "NvBbE5vYVPhidc?tiZ7E6DvP.z4bAQj29KEZOCv_XEl1pIn.Y1q8JoeGNoSelGj.db1iQpLM0fsype86LD.Vk.p6yweF5A2MlfxXDrEd7nz2SBExnTpp4QRN94pBAeulPLLtzqTz--y_UuF1g6cjE_.kuW_u5He0QkBdLMkyAgSx94N3Csj9LY37XOmUp9IIi9LXpTvZGa8oywp6JuMfhzwg5OCEvdp9mx.UyfQcnnJtYzzP5dItmwfEC-KJIvjvS8LF2NU2w2japQHtnAJqBAn3_EP-FN78wHnDEWANANT0cfor6kDqyKraO0Y-26PdB6xBjm3_VpU.8hnKIyoKdLQ6S.HZwr5rx0Bx76zXTCBv4uEzhtDFcDqVPN8ZG_kE90P..ldReG0jU4w3YA2jbaOgi6i-8llYWGoCiFFBm3Od-zLOEDYL2BlGsUFRUkiEMjytCVDqcIOdfPT7GQcd3wdmort6FFv8SbCu95f2gBCcM.5.ZmMxIOybubMGmiRunYM8-pSaVvXfBQSkM2Eygh15tkKCDHf8X3InAkPh7HQn13mP5y1gFRLsVAUWb-91PeHASP6hluUEdsX3uLQ9OJFenKrk.0zS9Goy08bfttd4h4Jtb2JV8vbJ8-3Wb4AJWqf0eUALMxOChB3sSBKW37s4vDb1NKOnoqOeoYQUBijqRGu9YLKIAimwo7Uvl0CuD7bWNrERweBqNVWjfGhlE8Yvvklm5YhCk5XY02pOa3IjMf_TDKhbTr8bh_20SXevnDk80XKg_3mWbhuieL23kx835AokAg9JpEkgydBBqo8nzQg23R5xJzKRT64kgb5GBlzuM9Oxh7pXsmzlYf"
	keyword        = "paperform"
)

func TestPaperform_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - with keyword paperform",
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
