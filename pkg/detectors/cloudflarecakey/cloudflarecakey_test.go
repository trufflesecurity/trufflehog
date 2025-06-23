package cloudflarecakey

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
			auth_type: "API-Key"
			base_url: "https://api.cloudflare.com/v1/user"
			ca_key: "v1.0-13vvv5141b975834504fc75b-a670d21e1e012816c3c8d9745e2693adc2d2ec7c402f607dbf7f2bd5de3bdb490cce4420ef13179957c5651e1ee5d952b1e03bd0271e2b43a9847f0713f4d3942cde4a7bc2e4770615"

		# Notes:
		# - Remember to rotate the secret every 90 days.
		# - The above credentials should only be used in a secure environment.
	`
	secret = "v1.0-13vvv5141b975834504fc75b-a670d21e1e012816c3c8d9745e2693adc2d2ec7c402f607dbf7f2bd5de3bdb490cce4420ef13179957c5651e1ee5d952b1e03bd0271e2b43a9847f0713f4d3942cde4a7bc2e4770615"
)

func TestCloudFlareCAKey_Pattern(t *testing.T) {
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
			want:  []string{secret},
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
