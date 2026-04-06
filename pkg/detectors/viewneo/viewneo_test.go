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
	// Realistic JWT-like viewneo bearer token: header.payload.signature
	// Matches the detector pattern: [a-z0-9A-Z]{120,300}.[a-z0-9A-Z]{150,300}.[a-z0-9A-Z-_]{600,800}
	validPattern = "NbrnTP3fAbnFbmOHnKYaXRvj7uff0LYTH8xIZM1JRcoreogrNwwmq6OLkTkx9NIQ0Wobtqn62tOy4CqpIqK3yn9FfcgMXAdx9G81aSQHqNgAC72qFl41sNLjVHWGaub52Z" +
		".td26fEeVVhDIq2AnHTmt9OBGhnuKoneNo41eoPni6JDWYlgAACTP9gyv1plBArp5B1Id9Z850kEnydx9qWCA79ISjs8JHUdKF0j7elKPoh3pKMzKG5mSoyPstUeC99enq522wjZRL9OaYsP6ihgIqLSmNqE40fAr" +
		".aXOqVJBae45I1Ljit5Y35npgX4ANj73-Z4bVv7Z3ZrYg32o0DtYobmv39rPz-I8h-l9qgBUuMGyKqTa7IUVQxeQvu2UttAzsiA8R5NtJasBLPDCnE5YkfGOv0WRombpE2eAOmSFpPaWXgBl9Hdp2DZQ_M85NUG1J5VEqpOXHOresruIioSTeAIAnA5LS2WyawW29AVIMooBbvRzkDiNbzKbPiDdynuWyW1qfbI_wPXPW8mbjiQKnSXkMVh09gbtR9zTeSOgX2Mh-YwBxGv20g9O1TBU9rZIEBUr21f4pDNyb2lnZv4Sra8fUFWSPFYfoStLEHBVvSrqhmhIWlnEU-HsgmolaIr-JSi3F3KECld8E0zeOdjKt_hWMYoHCC3_tNNV8nnQkleaCMsoTSDR7YOQ7BIP60ektVKshSS8GFfcBuqf91K8_RrcWEP6lLOFfwvQ2vSs80JDuu-zG_QIAmxWOWnJ7CSh-MpkJJf_6Dh1FTGr1-pJy6G43rYA7G0stL_FjIwJIDumSKoXcVTZyQ0-FcGL33CHDUAPjE-vSP222yuTW3ceO6_VBgO3CS5cYsxjHKYkf3Np6jDqqaZ5RkCwLOBq2myEpKK_s-QrKRVdMF5sZMwONRUQ1O5PtCLUfsVliI-H61q"

	// Invalid: character at position 60 replaced with ? which is not in [a-z0-9A-Z],
	// breaking the first segment's {120,300} alphanumeric requirement.
	invalidPattern = "NbrnTP3fAbnFbmOHnKYaXRvj7uff0LYTH8xIZM1JRcoreogrNwwmq6OLkT?x9NIQ0Wobtqn62tOy4CqpIqK3yn9FfcgMXAdx9G81aSQHqNgAC72qFl41sNLjVHWGaub52Z" +
		".td26fEeVVhDIq2AnHTmt9OBGhnuKoneNo41eoPni6JDWYlgAACTP9gyv1plBArp5B1Id9Z850kEnydx9qWCA79ISjs8JHUdKF0j7elKPoh3pKMzKG5mSoyPstUeC99enq522wjZRL9OaYsP6ihgIqLSmNqE40fAr" +
		".aXOqVJBae45I1Ljit5Y35npgX4ANj73-Z4bVv7Z3ZrYg32o0DtYobmv39rPz-I8h-l9qgBUuMGyKqTa7IUVQxeQvu2UttAzsiA8R5NtJasBLPDCnE5YkfGOv0WRombpE2eAOmSFpPaWXgBl9Hdp2DZQ_M85NUG1J5VEqpOXHOresruIioSTeAIAnA5LS2WyawW29AVIMooBbvRzkDiNbzKbPiDdynuWyW1qfbI_wPXPW8mbjiQKnSXkMVh09gbtR9zTeSOgX2Mh-YwBxGv20g9O1TBU9rZIEBUr21f4pDNyb2lnZv4Sra8fUFWSPFYfoStLEHBVvSrqhmhIWlnEU-HsgmolaIr-JSi3F3KECld8E0zeOdjKt_hWMYoHCC3_tNNV8nnQkleaCMsoTSDR7YOQ7BIP60ektVKshSS8GFfcBuqf91K8_RrcWEP6lLOFfwvQ2vSs80JDuu-zG_QIAmxWOWnJ7CSh-MpkJJf_6Dh1FTGr1-pJy6G43rYA7G0stL_FjIwJIDumSKoXcVTZyQ0-FcGL33CHDUAPjE-vSP222yuTW3ceO6_VBgO3CS5cYsxjHKYkf3Np6jDqqaZ5RkCwLOBq2myEpKK_s-QrKRVdMF5sZMwONRUQ1O5PtCLUfsVliI-H61q"

	keyword = "viewneo"
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
			name:  "valid pattern - realistic bearer token in config",
			input: fmt.Sprintf("# %s digital signage config\nVIEWNEO_API_TOKEN=\"%s\"", keyword, validPattern),
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
			name: "invalid pattern - bad character in token",
			input: `viewneo token = '` + invalidPattern + `'`,
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
