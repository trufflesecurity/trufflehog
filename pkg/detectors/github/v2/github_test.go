package github

import (
	"context"
	"hash/crc32"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validPattern = `[{
		"_id": "1a8d0cca-e1a9-4318-bc2f-f5658ab2dcb5",
		"name": "Github",
		"type": "Detector",
		"api": true,
		"authentication_type": "",
		"verification_url": "https://api.example.com/example",
		"test_secrets": {
			"github_secret": "ghs_RWGUZ6kS8_Ut7PbtR72k2miJwwYtxkpe8mOpT8feAWYZcwz43PxBVGCNATnycaQV9VUlPJe1uST5Xen7d3uZ5lilVlEVvT9AbxnhURdT3OzPtCvXydIrvE4LrDO"
		},
		"expected_response": "200",
		"method": "GET",
		"deprecated": false
	}]`
	secret            = "ghs_RWGUZ6kS8_Ut7PbtR72k2miJwwYtxkpe8mOpT8feAWYZcwz43PxBVGCNATnycaQV9VUlPJe1uST5Xen7d3uZ5lilVlEVvT9AbxnhURdT3OzPtCvXydIrvE4LrDO"
	fineGrainedSecret = "github_pat_" + strings.Repeat("A", 82)
)

func makeClassicToken(prefix, body string) string {
	return prefix + body + base62EncodePadded(uint64(crc32.ChecksumIEEE([]byte(body))), 6)
}

func TestGithub_Pattern(t *testing.T) {
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
		{
			name:  "valid github_pat pattern",
			input: fineGrainedSecret,
			want:  []string{fineGrainedSecret},
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

func TestGithub_ClassicTokenChecksum(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	body := "sbUsUmRNn8X74dFU0DJ9Fm1mvdCgtH"
	validToken := makeClassicToken("ghp_", body)
	invalidToken := "ghp_" + body + "AAAAAA"

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid classic token checksum",
			input: validToken,
			want:  []string{validToken},
		},
		{
			name:  "invalid classic token checksum",
			input: invalidToken,
			want:  nil,
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
				t.Errorf("expected %d results, only received %d", len(test.want), len(results))
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
