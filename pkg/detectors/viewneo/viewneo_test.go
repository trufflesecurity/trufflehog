package viewneo

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validPattern   = "cZZ32f1UDFCqsSP6uUlFyPLrXnGhgunvxc3jRsTO1mygukFtXxmk3sV0Q4PiGW8TstPPagjg8o3N0Jp25RKDJUOssch6rbSBVPc3R5vsRSa7y00CKKuu6T6N.2oV6hZlvOR7Jm3L6PzRLMbPRburA2FUfRlRLktcCbt2nBX1iyAfdMv8JvCjAhUJHT52PhiAT3ca7FNd5q5ZXAkn87LnuQhc5UHyuwD8gcWstOghUHZ20tcz7SjVuKyWZFgODlW2WczXqHKxaNhWYz4.839QXG7zlPYdYNhfbvQZe1zHr6bbbjIQYUs2q5whTtUWm8tCMWaOtm_DEZ_xKO5RUrajoClRedRiGK0fFAMshDSyAROOa7NXcE4WM_AuURDSif51QmcWY5HRITdd7y639Zc2Sz1kkUz-Ks_Aqe7xy0VUOlA8m4w2A7IfQ2iDtUeAlWIz1vsOihDxWeNqvTj5D5JOQcyRCiCfTfDWptrJCkKsMWMcDNRE773ypzQVn3r6VSVC63UqdT5Et5jpS5C1wFMuJDei5w7t4vPBTbodepVLtEkn4HcuyTEt0m-Rh_LIxMShlL56AeC7bVBNvvRpNMi_YT3wTozsXvAXEDS1bdOcD_MLk7-g8L1FfeBZxTnRfLR81idE4qR7ecTeNgfVvuiddb-IGrIAefADZ_Vzl49E3amY7twA7EqX04lBZiVfZsO1R0BlzsCLqQ10fsleLl-S00R01G1Fn2e2gkEkRkwOfxbA7BdTYJwz3s1m7rC2HmQLyT_-h8qE30fGzWkoq7INPSTmJ0EJOPDRY3TZi7axUSDEjZbF8TwXcD3jFDmaAYD3D4E5NSKnILnacXC-kfGZQcP4bcrPbHa4BoNN3kyt"
	invalidPattern = "c?Z32f1UDFCqsSP6uUlFyPLrXnGhgunvxc3jRsTO1mygukFtXxmk3sV0Q4PiGW8TstPPagjg8o3N0Jp25RKDJUOssch6rbSBVPc3R5vsRSa7y00CKKuu6T6N.2oV6hZlvOR7Jm3L6PzRLMbPRburA2FUfRlRLktcCbt2nBX1iyAfdMv8JvCjAhUJHT52PhiAT3ca7FNd5q5ZXAkn87LnuQhc5UHyuwD8gcWstOghUHZ20tcz7SjVuKyWZFgODlW2WczXqHKxaNhWYz4.839QXG7zlPYdYNhfbvQZe1zHr6bbbjIQYUs2q5whTtUWm8tCMWaOtm_DEZ_xKO5RUrajoClRedRiGK0fFAMshDSyAROOa7NXcE4WM_AuURDSif51QmcWY5HRITdd7y639Zc2Sz1kkUz-Ks_Aqe7xy0VUOlA8m4w2A7IfQ2iDtUeAlWIz1vsOihDxWeNqvTj5D5JOQcyRCiCfTfDWptrJCkKsMWMcDNRE773ypzQVn3r6VSVC63UqdT5Et5jpS5C1wFMuJDei5w7t4vPBTbodepVLtEkn4HcuyTEt0m-Rh_LIxMShlL56AeC7bVBNvvRpNMi_YT3wTozsXvAXEDS1bdOcD_MLk7-g8L1FfeBZxTnRfLR81idE4qR7ecTeNgfVvuiddb-IGrIAefADZ_Vzl49E3amY7twA7EqX04lBZiVfZsO1R0BlzsCLqQ10fsleLl-S00R01G1Fn2e2gkEkRkwOfxbA7BdTYJwz3s1m7rC2HmQLyT_-h8qE30fGzWkoq7INPSTmJ0EJOPDRY3TZi7axUSDEjZbF8TwXcD3jFDmaAYD3D4E5NSKnILnacXC-kfGZQcP4bcrPbHa4BoNN3kyt"
	keyword        = "viewneo"
)

func TestViewneo_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - with keyword viewneo",
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
