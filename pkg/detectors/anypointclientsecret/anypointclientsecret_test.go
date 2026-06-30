package anypointclientsecret

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestAnypointClientSecret_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "valid pattern with prefix",
			input: `
anypoint_client_id: a1b2c3d4e5f67890abcdef1234567890
anypoint_client_secret: A1B2C3D4E5F67890ABCDEF1234567890
`,
			want: []string{"a1b2c3d4e5f67890abcdef1234567890:A1B2C3D4E5F67890ABCDEF1234567890"},
		},
		{
			name: "valid pattern - config file format",
			input: `
ANYPOINT_CLIENT_ID=a1b2c3d4e5f67890abcdef1234567890
ANYPOINT_CLIENT_SECRET=A1B2C3D4E5F67890ABCDEF1234567890
`,
			want: []string{"a1b2c3d4e5f67890abcdef1234567890:A1B2C3D4E5F67890ABCDEF1234567890"},
		},
		{
			name: "invalid pattern - too short",
			input: `
anypoint_client_id: a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5
anypoint_client_secret: A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5
`,
			want: []string{},
		},
		{
			name: "invalid pattern - non-hex characters",
			input: `
anypoint_client_id: g1h2i3j4k5l6m7n8o9p0q1r2s3t4u5v6
anypoint_client_secret: G1H2I3J4K5L6M7N8O9P0Q1R2S3T4U5V6
`,
			want: []string{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 {
				if len(test.want) > 0 {
					t.Errorf("keywords '%v' not matched by: %s", d.Keywords(), test.input)
				}
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			if err != nil {
				t.Errorf("error = %v", err)
				return
			}

			if len(results) != len(test.want) {
				if len(results) == 0 {
					t.Errorf("did not receive any results")
				} else {
					t.Errorf("expected %d results, got %d", len(test.want), len(results))
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
