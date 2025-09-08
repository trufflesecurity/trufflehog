package airtableoauth

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
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
			name: "valid pattern",
			input: `
				[INFO] Sending request to the airtable API
				[DEBUG] Using Key=oaajtCy2lVMUN1Cm5.v1.eyJ1c2VySWQiOiJ1c3JjQ09QVlJudGlrU1lzdyIsImV4cGlyZXNBdCI6IjIwMjUtMDItMDNUMTk6NTY6MzcuMDAwWiIsIm9hdXRoQXBwbGljYXRpb25JZCI6Im9hcG14aXcyUlRrVGlzcHJIIiwic2VjcmV0IjoiMzczNThlNzdlZjlhMjljY2Q5MWIwNmNlNTdkZDYxNDg0MWVmNmIyOWYwYjQ5ZWE0MTMxZGI4NzBkNTAzYTE1NyJ9.0d67c8b334048135a93615610445e4aa90c6af6222392b49eea9419e1d6717d0
				[INFO] Response received: 200 OK
			`,
			want: []string{"oaajtCy2lVMUN1Cm5.v1.eyJ1c2VySWQiOiJ1c3JjQ09QVlJudGlrU1lzdyIsImV4cGlyZXNBdCI6IjIwMjUtMDItMDNUMTk6NTY6MzcuMDAwWiIsIm9hdXRoQXBwbGljYXRpb25JZCI6Im9hcG14aXcyUlRrVGlzcHJIIiwic2VjcmV0IjoiMzczNThlNzdlZjlhMjljY2Q5MWIwNmNlNTdkZDYxNDg0MWVmNmIyOWYwYjQ5ZWE0MTMxZGI4NzBkNTAzYTE1NyJ9.0d67c8b334048135a93615610445e4aa90c6af6222392b49eea9419e1d6717d0"},
		},
		{
			name: "valid pattern - xml",
			input: `
				<com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
  					<scope>GLOBAL</scope>
  					<id>{airtable}</id>
  					<secret>{airtable AQAAABAAA iKMJv6D1mmUvunFTZLfm4RrYhdrt5JCBMv.v1.r8IBnGw7b_vW0fl0MDJqPRUEsDdHtNYW9ANwPFm40V_M4knoEaulKL-5lmtWoRq9fjG-GORe8efob5e658nTiOkdYC.8a8d3}</secret>
  					<description>configuration for production</description>
					<creationDate>2023-05-18T14:32:10Z</creationDate>
  					<owner>jenkins-admin</owner>
				</com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
			`,
			want: []string{"iKMJv6D1mmUvunFTZLfm4RrYhdrt5JCBMv.v1.r8IBnGw7b_vW0fl0MDJqPRUEsDdHtNYW9ANwPFm40V_M4knoEaulKL-5lmtWoRq9fjG-GORe8efob5e658nTiOkdYC.8a8d3"},
		},
		{
			name: "finds all matches",
			input: `
				[INFO] Sending request to the airtable API
				[DEBUG] Using Key=oaajtCy2lVMUN1Cm5.v1.eyJ1c2VySWQiOiJ1c3JjQ09QVlJudGlrU1lzdyIsImV4cGlyZXNBdCI6IjIwMjUtMDItMDNUMTk6NTY6MzcuMDAwWiIsIm9hdXRoQXBwbGljYXRpb25JZCI6Im9hcG14aXcyUlRrVGlzcHJIIiwic2VjcmV0IjoiMzczNThlNzdlZjlhMjljY2Q5MWIwNmNlNTdkZDYxNDg0MWVmNmIyOWYwYjQ5ZWE0MTMxZGI4NzBkNTAzYTE1NyJ9.0d67c8b334048135a93615610445e4aa90c6af6222392b49eea9419e1d6717d0
				[ERROR] Response received: 401 UnAuthorized
				[DEBUG] Using Key=oaaRYiYSlTFXZzxDM.v1.eyJ1c2VySWQiOiJ1c3JjQ09QVlJudGlrU1lzdyIsIm9hdXRoQXBwbGljYXRpb25JZCI6Im9hcG14aXcyUlRrVGlzcHJIIiwiZXhwaXJlc0F0IjoiMjAyNS0wMS0yOVQwMDowMTo0NC4wMDBaIiwic2VjcmV0IjoiZjYyOWE1MWVkM2M0ZjU5ODlmOTcyMDU1ZjkwODk3NDA4NmU0NjQxY2JhODU5Y2FhZTJkZjliMWQwODg0ZjIzMiJ9.27a8998029ac9bdd599b435572821dcb63c60cbf62b9cb2ba2a73511e5553d66
				[INFO] Response received: 200 OK
			`,
			want: []string{
				"oaajtCy2lVMUN1Cm5.v1.eyJ1c2VySWQiOiJ1c3JjQ09QVlJudGlrU1lzdyIsImV4cGlyZXNBdCI6IjIwMjUtMDItMDNUMTk6NTY6MzcuMDAwWiIsIm9hdXRoQXBwbGljYXRpb25JZCI6Im9hcG14aXcyUlRrVGlzcHJIIiwic2VjcmV0IjoiMzczNThlNzdlZjlhMjljY2Q5MWIwNmNlNTdkZDYxNDg0MWVmNmIyOWYwYjQ5ZWE0MTMxZGI4NzBkNTAzYTE1NyJ9.0d67c8b334048135a93615610445e4aa90c6af6222392b49eea9419e1d6717d0",
				"oaaRYiYSlTFXZzxDM.v1.eyJ1c2VySWQiOiJ1c3JjQ09QVlJudGlrU1lzdyIsIm9hdXRoQXBwbGljYXRpb25JZCI6Im9hcG14aXcyUlRrVGlzcHJIIiwiZXhwaXJlc0F0IjoiMjAyNS0wMS0yOVQwMDowMTo0NC4wMDBaIiwic2VjcmV0IjoiZjYyOWE1MWVkM2M0ZjU5ODlmOTcyMDU1ZjkwODk3NDA4NmU0NjQxY2JhODU5Y2FhZTJkZjliMWQwODg0ZjIzMiJ9.27a8998029ac9bdd599b435572821dcb63c60cbf62b9cb2ba2a73511e5553d66",
			},
		},
		{
			name: "invalid pattern",
			input: `
				[INFO] Sending request to the airtable API
				[DEBUG] Using Key=oaaRYiYSlTFXZzxDM.v2.eyJ1c2VySWQiOiJ1c3JjQ09QVlJudGlrU1lzdyIsIm9hdXRoQXBwbGljYXRpb25JZCI6Im9hcG14aXcyUlRrVGlzcHJIIiwiZXhwaXJlc0F0IjoiMjAyNS0wMS0yOVQwMDowMTo0NC4wMDBaIiwic2VjcmV0IjoiZjYyOWE1MWVkM2M0ZjU5ODlmOTcyMDU1ZjkwODk3NDA4NmU0NjQxY2JhODU5Y2FhZTJkZjliMWQwODg0ZjIzMiJ9.27a8998029ac9bdd599b435572821dcb63c60cbf62b9cb2ba2a73511e5553d66
				[ERROR] Response received: 401 UnAuthorized
			`,
			want: []string{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 {
				t.Errorf("test %q failed: expected keywords %v to be found in the input", test.name, d.Keywords())
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			require.NoError(t, err)

			if len(results) != len(test.want) {
				t.Errorf("mismatch in result count: expected %d, got %d", len(test.want), len(results))
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
