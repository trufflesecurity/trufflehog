package heroku

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestHeroku_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "valid pattern",
			input: `[{
					"_id": "1a8d0cca-e1a9-4318-bc2f-f5658ab2dcb5",
					"name": "MyApp",
					"type": "Detector",
					"api": true,
					"authentication_type": "",
					"verification_url": "https://api.example.com/example",
					"test_secrets": {
						"secret1": "HRKU-AAlQ1aVoHDujJ9QsDHdHlHO0hbzhoERRSO45ZQusSYHg_____w4_hLrAym_u",
						"secret2": "HRKU-AAy9Ppr_HD2pPuTyIiTYInO0hbzhoERRSO93ZQusSYHgaD7_WQ07FnF7L9FX"
					},
					"expected_response": "200",
					"method": "GET",
					"deprecated": false
				}]`,
			want: []string{"HRKU-AAlQ1aVoHDujJ9QsDHdHlHO0hbzhoERRSO45ZQusSYHg_____w4_hLrAym_u", "HRKU-AAy9Ppr_HD2pPuTyIiTYInO0hbzhoERRSO93ZQusSYHgaD7_WQ07FnF7L9FX"},
		},
		{
			name: "invalid pattern",
			input: `[{
					"_id": "1a8d0cca-e1a9-4318-bc2f-f5658ab2dcb5",
					"name": "MyApp",
					"type": "Detector",
					"api": true,
					"authentication_type": "",
					"verification_url": "https://api.example.com/example",
					"test_secrets": {
						"secret1": "HRKU-AAlQ1aVoHDujJ9QsDHdHlHO0hbzoERRSO45ZQusSYHg_____w4_hLrAym_u",
						"secret2": "HRKU-AAy9Ppr_HD2pPuTyIiTYInO0h;zhoERRSO93ZQusSYHgaD7_WQ07FnF7L9FX"
					},
					"expected_response": "200",
					"method": "GET",
					"deprecated": false
				}]`,
			want: []string{},
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
