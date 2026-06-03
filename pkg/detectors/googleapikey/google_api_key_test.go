package googleapikey

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

func TestGoogleApiKey_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "valid pattern - assignment context",
			input: `GOOGLE_API_KEY = "AIzaSyD-9tSrke72I6e0DVQ9y_VoqTepV9AEAZE"`,
			want:  []string{"AIzaSyD-9tSrke72I6e0DVQ9y_VoqTepV9AEAZE"},
		},
		{
			name: "valid pattern - env file",
			input: `MAPS_KEY=AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI
                    DATABASE_URL=postgres://localhost/mydb`,
			want: []string{"AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI"},
		},
		{
			name: "valid pattern - multiple keys",
			input: `key1: AIzaSyD-9tSrke72I6e0DVQ9y_VoqTepV9AEAZE
                    key2: AIzaSyBa3j4ker72I6e0DVQ9y_VoqTepV9AEBZE`,
			want: []string{
				"AIzaSyD-9tSrke72I6e0DVQ9y_VoqTepV9AEAZE",
				"AIzaSyBa3j4ker72I6e0DVQ9y_VoqTepV9AEBZE",
			},
		},
		{
			name:  "valid pattern - xml",
			input: `<secret>{AQAAABAAA AIzaSyD-9tSrke72I6e0DVQ9y_VoqTepV9AEAZE}</secret>`,
			want:  []string{"AIzaSyD-9tSrke72I6e0DVQ9y_VoqTepV9AEAZE"},
		},
		{
			name:  "deduplication - repeated key",
			input: `AIzaSyD-9tSrke72I6e0DVQ9y_VoqTepV9AEAZE AIzaSyD-9tSrke72I6e0DVQ9y_VoqTepV9AEAZE`,
			want:  []string{"AIzaSyD-9tSrke72I6e0DVQ9y_VoqTepV9AEAZE"},
		},
		{
			name:  "invalid pattern - too short",
			input: `key = "AIzaSyD-9tSrke72I6e0DVQ"`,
			want:  nil,
		},
		{
			name:  "invalid pattern - wrong prefix",
			input: `key = "AIzBSyD-9tSrke72I6e0DVQ9y_VoqTepV9AEAZE"`,
			want:  nil,
		},
		{
			name:  "invalid pattern - invalid characters",
			input: `key = "AIzaSyD-9tSrke72I6e0DVQ9y_VoqTepV9AEA!E"`,
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

// TestGoogleApiKey_Type asserts the detector reports the exact expected type,
// not just any non-empty string.
func TestGoogleApiKey_Type(t *testing.T) {
	s := Scanner{}
	require.Equal(t, detector_typepb.DetectorType_GoogleApiKey, s.Type())
}

// TestGoogleApiKey_Keywords asserts the "AIza" prefix is present in the
// keyword list used for AhoCorasick pre-filtering.
func TestGoogleApiKey_Keywords(t *testing.T) {
	s := Scanner{}
	require.NotEmpty(t, s.Keywords())
	require.Contains(t, s.Keywords(), "AIza")
}
