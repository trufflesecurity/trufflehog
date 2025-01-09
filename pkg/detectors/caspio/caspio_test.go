package caspio

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validPattern = `
		# Configuration File: config.yaml
		database:
			host: $DB_HOST
			port: $DB_PORT
			username: $DB_USERNAME
			password: $DB_PASS  # IMPORTANT: Do not share this password publicly

		api:
			caspio_id: "qye6c979b55w55hz7nqrdgax3pufdsigwvhofsrxalgk01asty"
			caspio_secret: "x5vzi1o2fmnjywilv3obwx5n041f56v54lgral6znyccet8ibe"
			caspio_domain: xlo0xo2s
			auth_type: Client Credentials
			base_url: "https://$caspio_domain.caspio.com/v1/user"
			auth_token: ""

		# Notes:
		# - Remember to rotate the secret every 90 days.
		# - The above credentials should only be used in a secure environment.
	`
	secrets = []string{
		"qye6c979b55w55hz7nqrdgax3pufdsigwvhofsrxalgk01astyqye6c979b55w55hz7nqrdgax3pufdsigwvhofsrxalgk01astyxlo0xo2s",
		"qye6c979b55w55hz7nqrdgax3pufdsigwvhofsrxalgk01astyx5vzi1o2fmnjywilv3obwx5n041f56v54lgral6znyccet8ibexlo0xo2s",
		"x5vzi1o2fmnjywilv3obwx5n041f56v54lgral6znyccet8ibeqye6c979b55w55hz7nqrdgax3pufdsigwvhofsrxalgk01astyxlo0xo2s",
		"x5vzi1o2fmnjywilv3obwx5n041f56v54lgral6znyccet8ibex5vzi1o2fmnjywilv3obwx5n041f56v54lgral6znyccet8ibexlo0xo2s",
	}
)

func TestCaspio_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern",
			input: validPattern,
			want:  secrets,
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
