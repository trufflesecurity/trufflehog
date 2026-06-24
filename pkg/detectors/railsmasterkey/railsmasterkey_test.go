package railsmasterkey

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

const (
	// Replace with your actual Rails master key for testing
	validRailsKey = "7722fb3541892dcb989dc0d425362493"
)

func TestRailsmasterkey_FromData_Verification(t *testing.T) {
	ctx := context.Background()
	s := Scanner{}

	tests := []struct {
		name       string
		data       string
		verify     bool
		wantVerify bool
		wantErr    bool
	}{
		{
			name:       "valid Rails master key",
			data:       "RAILS_MASTER_KEY=" + validRailsKey,
			verify:     true,
			wantVerify: true,
			wantErr:    false,
		},
		{
			name:       "no verification",
			data:       "RAILS_MASTER_KEY=" + validRailsKey,
			verify:     false,
			wantVerify: false,
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if validRailsKey == "PASTE_YOUR_REAL_RAILS_MASTER_KEY_HERE" {
				t.Skip("Skipping test: Replace validRailsKey with an actual Rails master key")
			}

			results, err := s.FromData(ctx, tt.verify, []byte(tt.data))
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotEmpty(t, results)

			if tt.verify {
				t.Logf("✅ Key detected: %s", string(results[0].Raw))
				t.Logf("✅ Verified: %v", results[0].Verified)
				require.Equal(t, tt.wantVerify, results[0].Verified, "Verification result mismatch")
			}
		})
	}
}

func TestRailsmasterkey_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "valid pattern - env file",
			input: `
				RAILS_MASTER_KEY=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
			`,
			want: []string{"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
		},
		{
			name: "valid pattern - config file",
			input: `
				# config/master.key
				abc123def456789012345678901234567890abcdefabcdefabcdef0123456789
			`,
			want: []string{"abc123def456789012345678901234567890abcdefabcdefabcdef0123456789"},
		},
		{
			name: "finds multiple matches",
			input: `
				RAILS_MASTER_KEY=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
				BACKUP_KEY=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210
			`,
			want: []string{
				"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
				"fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
			},
		},
		{
			name: "invalid pattern - wrong length",
			input: `
				RAILS_MASTER_KEY=0123456789abcdef
			`,
			want: []string{},
		},
		{
			name: "invalid pattern - contains uppercase hex (not pure hex)",
			input: `
				RAILS_MASTER_KEY=0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
			`,
			want: []string{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 {
				if len(test.want) > 0 {
					t.Errorf("test %q failed: expected keywords %v to be found in the input", test.name, d.Keywords())
				}
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
