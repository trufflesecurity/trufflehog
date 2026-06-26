package newrelicbrowserkey

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

const (
	// PASTE YOUR ACTUAL BROWSER KEY BELOW (revert before commit!)
	validKey   = ""  // Replace with actual key for local testing
	invalidKey = "NRBR-0000000000000000000"
)

func TestNewRelicBrowserKey_FromData_Verification(t *testing.T) {
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
			name:       "valid New Relic Browser key",
			data:       "NEWRELIC_BROWSER_KEY=" + validKey,
			verify:     true,
			wantVerify: true,
			wantErr:    false,
		},
		{
			name:       "invalid New Relic Browser key - format valid but fake",
			data:       "NEWRELIC_BROWSER_KEY=" + invalidKey,
			verify:     true,
			wantVerify: true, // Format-only verification returns true for valid format
			wantErr:    false,
		},
		{
			name:       "no verification",
			data:       "NEWRELIC_BROWSER_KEY=" + validKey,
			verify:     false,
			wantVerify: false,
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if validKey == "" {
				t.Skip("Skipping test: Replace validKey with an actual New Relic Browser key")
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
				t.Logf("✅ ExtraData: %v", results[0].ExtraData)
				require.Equal(t, tt.wantVerify, results[0].Verified, "Verification result mismatch")
			}
		})
	}
}

func TestNewRelicBrowserKey_Pattern(t *testing.T) {
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
				NEW_RELIC_BROWSER_KEY=NRBR-abc123def456ghi789
			`,
			want: []string{"NRBR-abc123def456ghi789"},
		},
		{
			name: "valid pattern - config file",
			input: `
				{
					"newrelic": {
						"browser_key": "NRBR-1234567890abcdefABCDEF"
					}
				}
			`,
			want: []string{"NRBR-1234567890abcdefABCDEF"},
		},
		{
			name: "valid pattern - rum config",
			input: `
				<script>
				NREUM.info = {
					licenseKey: "NRBR-fedcba0987654321FEDCBA",
					applicationID: "12345"
				}
				</script>
			`,
			want: []string{"NRBR-fedcba0987654321FEDCBA"},
		},
		{
			name: "invalid pattern - too short",
			input: `
				NEW_RELIC_BROWSER_KEY=short123
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
