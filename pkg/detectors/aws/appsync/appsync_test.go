package appsync

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestAppSync_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "valid pattern - key and endpoint",
			input: `
				const endpoint = "https://abcdefghijklmnopqrstuvwxyz.appsync-api.us-east-1.amazonaws.com/graphql";
				const key = "da2-abcdefghijklmnopqrstuvwxyz";
			`,
			want: []string{
				"https://abcdefghijklmnopqrstuvwxyz.appsync-api.us-east-1.amazonaws.com/graphql:da2-abcdefghijklmnopqrstuvwxyz",
			},
		},
		{
			name: "valid pattern - key and endpoint(endpoint without /graphql)",
			input: `
				const endpoint = "https://abcdefghijklmnopqrstuvwxyz.appsync-api.us-east-1.amazonaws.com";
				const key = "da2-abcdefghijklmnopqrstuvwxyz";
			`,
			want: []string{
				"https://abcdefghijklmnopqrstuvwxyz.appsync-api.us-east-1.amazonaws.com/graphql:da2-abcdefghijklmnopqrstuvwxyz",
			},
		},
		{
			name: "valid pattern - multiple keys and endpoints",
			input: `
				https://aaaaaaaaaaaaaaaaaaaaaaaaaa.appsync-api.us-west-2.amazonaws.com/graphql
				da2-aaaaaaaaaaaaaaaaaaaaaaaaaa

				https://bbbbbbbbbbbbbbbbbbbbbbbbbb.appsync-api.eu-central-1.amazonaws.com/graphql
				da2-bbbbbbbbbbbbbbbbbbbbbbbbbb
			`,
			want: []string{
				"https://aaaaaaaaaaaaaaaaaaaaaaaaaa.appsync-api.us-west-2.amazonaws.com/graphql:da2-aaaaaaaaaaaaaaaaaaaaaaaaaa",
				"https://bbbbbbbbbbbbbbbbbbbbbbbbbb.appsync-api.eu-central-1.amazonaws.com/graphql:da2-aaaaaaaaaaaaaaaaaaaaaaaaaa",
				"https://aaaaaaaaaaaaaaaaaaaaaaaaaa.appsync-api.us-west-2.amazonaws.com/graphql:da2-bbbbbbbbbbbbbbbbbbbbbbbbbb",
				"https://bbbbbbbbbbbbbbbbbbbbbbbbbb.appsync-api.eu-central-1.amazonaws.com/graphql:da2-bbbbbbbbbbbbbbbbbbbbbbbbbb",
			},
		},
		{
			name: "invalid pattern - uppercase key",
			input: `
				https://abcdefghijklmnopqrstuvwxyz.appsync-api.us-east-1.amazonaws.com/graphql
				da2-ABCDEFGHIJKLMNOPQRSTUVWXYZ
			`,
			want: nil,
		},
		{
			name: "invalid pattern - key too short",
			input: `
				https://abcdefghijklmnopqrstuvwxyz.appsync-api.us-east-1.amazonaws.com/graphql
				da2-abc123
			`,
			want: nil,
		},
		{
			name: "invalid pattern - key only",
			input: `
				da2-abcdefghijklmnopqrstuvwxyz
			`,
			want: nil,
		},
		{
			name: "invalid pattern - malformed endpoint",
			input: `
				https://abc.appsync-api.us-east-1.amazonaws.com/graphql
				da2-abcdefghijklmnopqrstuvwxyz
			`,
			want: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 {
				t.Errorf(
					"test %q failed: expected keywords %v to be found in the input",
					test.name,
					d.Keywords(),
				)
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			require.NoError(t, err)

			if len(results) != len(test.want) {
				t.Errorf(
					"mismatch in result count: expected %d, got %d",
					len(test.want),
					len(results),
				)
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
