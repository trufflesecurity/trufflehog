package caflou

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestCaflou_Pattern(t *testing.T) {
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
					# Configuration File: config.yaml
					database:
						host: $DB_HOST
						port: $DB_PORT
						username: $DB_USERNAME
						password: $DB_PASS  # IMPORTANT: Do not share this password publicly

					api:
						base_url: "https://api.example.com/instances"
						api_key: $API_KEY
						caflou_auth_token: "Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX9lkIjo1OTQ5MCwianCpIjoiOTQwZjBlODkxNPhhZjM4OTQ1OGQwMDIxIiziZXhwIjoxGzU1MTk4MDAwfQ.EMNGCPX7aNIvriX360oLFAgMwHeXxKD7N4kdcJtPqTI"

					# Notes:
					# - Remember to rotate the secret every 90 days.
					# - The above credentials should only be used in a secure environment.
				`,
			want: []string{"eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX9lkIjo1OTQ5MCwianCpIjoiOTQwZjBlODkxNPhhZjM4OTQ1OGQwMDIxIiziZXhwIjoxGzU1MTk4MDAwfQ.EMNGCPX7aNIvriX360oLFAgMwHeXxKD7N4kdcJtPqTI"},
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
