package airtableoauth

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validPattern1  = "oaajtCy2lVMUN1Cm5.v1.eyJ1c2VySWQiOiJ1c3JjQ09QVlJudGlrU1lzdyIsImV4cGlyZXNBdCI6IjIwMjUtMDItMDNUMTk6NTY6MzcuMDAwWiIsIm9hdXRoQXBwbGljYXRpb25JZCI6Im9hcG14aXcyUlRrVGlzcHJIIiwic2VjcmV0IjoiMzczNThlNzdlZjlhMjljY2Q5MWIwNmNlNTdkZDYxNDg0MWVmNmIyOWYwYjQ5ZWE0MTMxZGI4NzBkNTAzYTE1NyJ9.0d67c8b334048135a93615610445e4aa90c6af6222392b49eea9419e1d6717d0"
	validPattern2  = "oaaRYiYSlTFXZzxDM.v1.eyJ1c2VySWQiOiJ1c3JjQ09QVlJudGlrU1lzdyIsIm9hdXRoQXBwbGljYXRpb25JZCI6Im9hcG14aXcyUlRrVGlzcHJIIiwiZXhwaXJlc0F0IjoiMjAyNS0wMS0yOVQwMDowMTo0NC4wMDBaIiwic2VjcmV0IjoiZjYyOWE1MWVkM2M0ZjU5ODlmOTcyMDU1ZjkwODk3NDA4NmU0NjQxY2JhODU5Y2FhZTJkZjliMWQwODg0ZjIzMiJ9.27a8998029ac9bdd599b435572821dcb63c60cbf62b9cb2ba2a73511e5553d66"
	invalidPattern = "oaaRYiYSlTFXZzxDM.v2.eyJ1c2VySWQiOiJ1c3JjQ09QVlJudGlrU1lzdyIsIm9hdXRoQXBwbGljYXRpb25JZCI6Im9hcG14aXcyUlRrVGlzcHJIIiwiZXhwaXJlc0F0IjoiMjAyNS0wMS0yOVQwMDowMTo0NC4wMDBaIiwic2VjcmV0IjoiZjYyOWE1MWVkM2M0ZjU5ODlmOTcyMDU1ZjkwODk3NDA4NmU0NjQxY2JhODU5Y2FhZTJkZjliMWQwODg0ZjIzMiJ9.27a8998029ac9bdd599b435572821dcb63c60cbf62b9cb2ba2a73511e5553d66"
)

func TestAirtableoauth_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "typical pattern",
			input: fmt.Sprintf("airtable token = '%s'", validPattern1),
			want:  []string{validPattern1},
		},
		{
			name: "finds all matches",
			input: fmt.Sprintf(`airtable token 1 = '%s'
			airtabl token 2 = '%s'`, validPattern1, validPattern2),
			want: []string{validPattern1, validPattern2},
		},
		{
			name:  "invalid pattern",
			input: fmt.Sprintf("airtable token = '%s'", invalidPattern),
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
