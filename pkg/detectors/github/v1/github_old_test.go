package github

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestGithub_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "valid pattern",
			input: `[{
				"_id": "1a8d0cca-e1a9-4318-bc2f-f5658ab2dcb5",
				"name": "Github",
				"type": "Detector",
				"api": true,
				"authentication_type": "",
				"verification_url": "https://api.example.com/example",
				"test_secrets": {
					"github_secret": "abc123def4567890abcdef1234567890abcdef12"
				},
				"expected_response": "200",
				"method": "GET",
				"deprecated": false
			}]`,
			want: []string{"abc123def4567890abcdef1234567890abcdef12"},
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

func Test_isKnownNonSensitiveCommonPrefix(t *testing.T) {
	type args struct {
		matchPrefix string
	}
	tests := []struct {
		name          string
		args          args
		isKnownPrefix bool
	}{
		{
			name:          "repo url",
			args:          args{matchPrefix: "github.com/repos/symfony/monolog-bridge/zipball/9d14621e59f22c2b6d030d92d37ffe5ae1e60452"},
			isKnownPrefix: true,
		},
		{
			name:          "sha256 hash",
			args:          args{matchPrefix: "Digest: sha256:f9a92af4d46ca171bffa5c00509414a19d9887c9ed4fe98d1f43757b52600e39"},
			isKnownPrefix: true,
		},
		{
			name:          "real looking token",
			args:          args{matchPrefix: "github-app-token@df432ceedc7162793a195dd1713ff69aefc7379e"},
			isKnownPrefix: false,
		},
		{
			name:          "github url",
			args:          args{matchPrefix: "github.com/wrandelshofer/FastDoubleParser/blob/39e123b15b71f29a38a087d16a0bc620fc879aa6/bigint-LICENSE"},
			isKnownPrefix: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isKnownNonSensitiveCommonPrefix(tt.args.matchPrefix); got != tt.isKnownPrefix {
				t.Errorf("isKnownNonSensitiveCommonPrefix() = %v, want %v", got, tt.isKnownPrefix)
			}
		})
	}
}
