package octopusapikey

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

func TestOctopusApiKey_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - header usage",
			input: `X-Octopus-ApiKey: API-ZNRMR7SL6L3ATMOIK7GKJDKLPY`,
			want:  []string{"API-ZNRMR7SL6L3ATMOIK7GKJDKLPY"},
		},
		{
			name:  "valid pattern - env assignment",
			input: `OCTOPUS_API_KEY="API-7F1M9T3D5P7Q2W4R6Y8U0I2O4A"`,
			want:  []string{"API-7F1M9T3D5P7Q2W4R6Y8U0I2O4A"},
		},
		{
			name: "valid pattern - multiple keys",
			input: `octopus primary=API-ZNRMR7SL6L3ATMOIK7GKJDKLPY
octopus backup=API-1A2B3C4D5E6F7G8H9I0J1K2L3M`,
			want: []string{
				"API-ZNRMR7SL6L3ATMOIK7GKJDKLPY",
				"API-1A2B3C4D5E6F7G8H9I0J1K2L3M",
			},
		},
		{
			name:  "deduplication - repeated key",
			input: `octopus API-ZNRMR7SL6L3ATMOIK7GKJDKLPY octopus API-ZNRMR7SL6L3ATMOIK7GKJDKLPY`,
			want:  []string{"API-ZNRMR7SL6L3ATMOIK7GKJDKLPY"},
		},
		{
			name:  "invalid pattern - too short",
			input: `key = "API-ABC123"`,
			want:  nil,
		},
		{
			name:  "invalid pattern - lowercase characters",
			input: `key = "API-ZNRMR7SL6L3ATMOIK7GkJDKLPY"`,
			want:  nil,
		},
		{
			name:  "invalid pattern - wrong prefix",
			input: `key = "AP1-ZNRMR7SL6L3ATMOIK7GKJDKLPY"`,
			want:  nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(test.want) > 0 && len(matchedDetectors) == 0 {
				t.Errorf("keywords %v not found in input", d.Keywords())
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			require.NoError(t, err)

			if len(results) != len(test.want) {
				t.Errorf("expected %d results, got %d", len(test.want), len(results))
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

func TestOctopusApiKey_Type(t *testing.T) {
	s := Scanner{}
	require.Equal(t, detector_typepb.DetectorType_OctopusApiKey, s.Type())
}

func TestOctopusApiKey_Keywords(t *testing.T) {
	s := Scanner{}
	require.NotEmpty(t, s.Keywords())
	require.Contains(t, s.Keywords(), "octopus")
	require.Contains(t, s.Keywords(), "X-Octopus-ApiKey")
}
