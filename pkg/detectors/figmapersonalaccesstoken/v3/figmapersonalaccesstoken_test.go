package figmapersonalaccesstoken

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

var (
	validPattern = `[{
		"_id": "1a8d0cca-e1a9-4318-bc2f-f5658ab2dcb5",
		"name": "FigmaV3",
		"type": "Detector",
		"api": true,
		"authentication_type": "",
		"verification_url": "https://api.figma.com/v1/me",
		"test_secrets": {
			"figma_secret": "figp_EZe7plhYvN92IyiDCjkvTcbNVZsuRVpDcHOwNNP1"
		},
		"expected_response": "200",
		"method": "GET",
		"deprecated": false
	}]`
	secret = "figp_EZe7plhYvN92IyiDCjkvTcbNVZsuRVpDcHOwNNP1"

	invalidPatterns = []string{
		`figp_short`, // too short
		`figd_EZe7plhYvN92IyiDCjkvTcbNVZsuRVpDcHOwNNP1`,       // wrong prefix (v2 token)
		`figp_!!!invalid_chars_here!!!!!!!!!!!!!!!!!!!!!!!!!`, // invalid characters
	}
)

func TestFigmaPersonalAccessToken_Pattern(t *testing.T) {
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

func TestFigmaPersonalAccessToken_InvalidPatterns(t *testing.T) {
	d := Scanner{}

	for _, input := range invalidPatterns {
		t.Run(input, func(t *testing.T) {
			results, err := d.FromData(context.Background(), false, []byte(input))
			if err != nil {
				t.Errorf("error = %v", err)
				return
			}
			if len(results) != 0 {
				t.Errorf("expected no results for invalid input %q, got %d", input, len(results))
			}
		})
	}
}
