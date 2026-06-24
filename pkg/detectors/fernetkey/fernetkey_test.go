package fernetkey

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

const (
	// Replace with your actual Fernet key for testing
	validFernetKey = "zuSJOxaVmOMHWcq_HY7DUD849z30znbS3RNKrL7XPK0="
)

func TestFernetkey_FromData_Verification(t *testing.T) {
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
			name:       "valid Fernet key",
			data:       "fernet_key: " + validFernetKey,
			verify:     true,
			wantVerify: true,
			wantErr:    false,
		},
		{
			name:       "no verification",
			data:       "fernet_key: " + validFernetKey,
			verify:     false,
			wantVerify: false,
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if validFernetKey == "PASTE_YOUR_REAL_FERNET_KEY_HERE" {
				t.Skip("Skipping test: Replace validFernetKey with an actual Fernet key")
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

func TestFernetkey_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "valid pattern - config file",
			input: `
				FERNET_KEY=cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=
			`,
			want: []string{"cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4="},
		},
		{
			name: "valid pattern - python code",
			input: `
				from cryptography.fernet import Fernet
				key = b'u3Uc-qAi9iiCv3fkBfRUAKrM1gH8w51-nVU8M8A7Fy8='
			`,
			want: []string{"u3Uc-qAi9iiCv3fkBfRUAKrM1gH8w51-nVU8M8A7Fy8="},
		},
		{
			name: "finds multiple matches",
			input: `
				FERNET_KEY_1=cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=
				FERNET_KEY_2=u3Uc-qAi9iiCv3fkBfRUAKrM1gH8w51-nVU8M8A7Fy8=
			`,
			want: []string{"cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=", "u3Uc-qAi9iiCv3fkBfRUAKrM1gH8w51-nVU8M8A7Fy8="},
		},
		{
			name: "invalid pattern - wrong length",
			input: `
				FERNET_KEY=cw_0x689RpI-jtRR7oE8h_eQsKImv=
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
