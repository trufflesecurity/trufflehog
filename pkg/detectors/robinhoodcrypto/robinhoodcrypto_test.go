package robinhoodcrypto

import (
	"context"
	"github.com/google/go-cmp/cmp"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
	"testing"
)

func TestRobinhoodCrypto_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "typical pattern",
			input: `
				api_key = "rh-api-e3bb245e-a45c-4729-8a9b-10201756f8cc"
				private_key_base64 = "aVhXn8ghC9YqSz5RyFuKc6SsDC6SuPIqSW3IXH76ZlMCjOxkazBQjQFucJLk3uNorpBt6TbYpo/D1lHA7s4+hQ=="
			`,
			want: []string{
				"rh-api-e3bb245e-a45c-4729-8a9b-10201756f8cc" +
					"aVhXn8ghC9YqSz5RyFuKc6SsDC6SuPIqSW3IXH76ZlMCjOxkazBQjQFucJLk3uNorpBt6TbYpo/D1lHA7s4+hQ==",
			},
		},
	}

	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
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
			},
		)
	}
}
