package allsports

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestAllSports_Pattern(t *testing.T) {
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
				[INFO] Sending request to the allsports API
				[DEBUG] Using Key=cq73u5azj3p3shfvzz3lw1typfqu6uduq7bophtq4veta7cnvd4s5htkb8lgk4vr
				[INFO] Response received: 200 OK
			`,
			want: []string{"cq73u5azj3p3shfvzz3lw1typfqu6uduq7bophtq4veta7cnvd4s5htkb8lgk4vr"},
		},
		{
			name: "valid pattern - xml",
			input: `
				<com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
  					<scope>GLOBAL</scope>
  					<id>{allsports}</id>
  					<secret>{AQAAABAAA bj8yzu3awie5akwiwcb7esqygqx14gt65j9lrcpec0v28ckkswtyza1x9747gap5}</secret>
  					<description>configuration for production</description>
					<creationDate>2023-05-18T14:32:10Z</creationDate>
  					<owner>jenkins-admin</owner>
				</com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
			`,
			want: []string{"bj8yzu3awie5akwiwcb7esqygqx14gt65j9lrcpec0v28ckkswtyza1x9747gap5"},
		},
		{
			name: "valid pattern - key out of prefix range",
			input: `
				[DEBUG] allsports api processing
				[INFO] Sending request to the API
				[DEBUG] Using Key=cq73u5azj3p3shfvzz3lw1typfqu6uduq7bophtq4veta7cnvd4s5htkb8lgk4vr
				[INFO] Response received: 200 OK
			`,
			want: nil,
		},
		{
			name: "invalid pattern",
			input: `
				[INFO] Sending request to the allsports API
				[DEBUG] Using Key=d1f2e3c4b5a6d7e8f9G0h1i2j3k4l5m6n7o8p9q0r1s2t3u4v5w6x7y8z9a0b1ce
				[INFO] Response received: 200 OK
			`,
			want: nil,
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
