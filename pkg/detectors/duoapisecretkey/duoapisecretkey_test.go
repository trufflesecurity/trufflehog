package duoapisecretkey

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

func TestDuoapisecretkey_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "valid duo secret key pattern",
			input: `
				[INFO] Configuring Duo Security
				[DEBUG] Using duo_secret_key=abcdef1234567890abcdef1234567890abcdef12
				[INFO] Integration configured successfully
			`,
			want: []string{"abcdef1234567890abcdef1234567890abcdef12"},
		},
		{
			name: "valid pattern with integration key and host",
			input: `
				duo_integration_key = DI5P23TOPGW6BJRIL549
				duo_secret_key = s8mEh9IO9toOzaZHzZWnrhZ6Bbvh7QkpRssXu1Kn
				duo_api_host = api-6cf7c0a0.duosecurity.com
			`,
			want: []string{"s8mEh9IO9toOzaZHzZWnrhZ6Bbvh7QkpRssXu1Kn"},
		},
		{
			name: "finds duo secret in config file",
			input: `
				[duo]
				integration_key = DIABC123456789012345
				secret_key = abcd1234567890abcd1234567890abcd12345678
				api_hostname = api-abcd1234.duosecurity.com
			`,
			want: []string{"abcd1234567890abcd1234567890abcd12345678"},
		},
		{
			name: "invalid pattern - too short",
			input: `
				[INFO] duo_secret_key=abcdef123456789
				[ERROR] Invalid secret key length
			`,
			want: []string{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 {
				t.Errorf("test %q failed: expected keywords %v to be found in the input", test.name, d.Keywords())
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

// TestDuoapisecretkey_FromData_WithVerification tests the detector with actual verification
// Replace the placeholder values with real Duo API credentials to test verification
func TestDuoapisecretkey_FromData_WithVerification(t *testing.T) {
	// IMPORTANT: Replace these with your actual Duo API credentials for testing
	// You can get these from your Duo Admin Panel -> Applications -> Protect an Application
	const (
		// Your active Duo Integration Key (format: DI followed by 18 alphanumeric characters)
		testIntegrationKey = "DIC5F5ICX1ZA69HQ7MWP"

		// Your active Duo Secret Key (40 hexadecimal characters)
		testSecretKey = "HJhJempPXEHVJmol73aKqcTqpzvkR2B9EUzjSJvb"

		// Your Duo API Hostname (format: api-xxxxxxxx.duosecurity.com)
		testAPIHost = "api-6cf7c0a0.duosecurity.com"

		// An invalid secret key for negative testing (must be 40 hex chars but invalid)
		testInvalidSecretKey = "0000000000000000000000000000000000000000"
	)

	// Skip this test if using placeholder values
	if testIntegrationKey == "DIABC123456789012345" {
		t.Skip("Skipping verification test - please provide real Duo API credentials in the test constants")
	}

	d := Scanner{}
	ctx := context.Background()

	tests := []struct {
		name           string
		data           string
		verify         bool
		wantVerified   bool
		wantDetections int
	}{
		{
			name: "valid credentials - detected but not verified (Duo requires signature auth)",
			data: fmt.Sprintf(`
				[duo]
				integration_key = %s
				secret_key = %s
				api_hostname = %s
			`, testIntegrationKey, testSecretKey, testAPIHost),
			verify:         true,
			wantVerified:   false, // Duo API requires HMAC-SHA1 signature, not implemented yet
			wantDetections: 1,
		},
		{
			name: "invalid secret key - should detect but not verify",
			data: fmt.Sprintf(`
				[duo]
				integration_key = %s
				secret_key = %s
				api_hostname = %s
			`, testIntegrationKey, testInvalidSecretKey, testAPIHost),
			verify:         true,
			wantVerified:   false,
			wantDetections: 1,
		},
		{
			name: "valid credentials in different format - detected but not verified",
			data: fmt.Sprintf(`
				DUO_INTEGRATION_KEY=%s
				DUO_SECRET_KEY=%s
				DUO_API_HOST=%s
			`, testIntegrationKey, testSecretKey, testAPIHost),
			verify:         true,
			wantVerified:   false, // Duo API requires HMAC-SHA1 signature, not implemented yet
			wantDetections: 1,
		},
		{
			name: "detect without verification",
			data: fmt.Sprintf(`
				duo_secret=%s
			`, testSecretKey),
			verify:         false,
			wantVerified:   false,
			wantDetections: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results, err := d.FromData(ctx, tt.verify, []byte(tt.data))
			require.NoError(t, err)

			if len(results) != tt.wantDetections {
				t.Errorf("expected %d detections, got %d", tt.wantDetections, len(results))
				return
			}

			if len(results) > 0 {
				result := results[0]

				// Check detector type
				if result.DetectorType != detector_typepb.DetectorType_DuoAPISecretKey {
					t.Errorf("expected detector type DuoAPISecretKey, got %v", result.DetectorType)
				}

				// Check verification status
				if tt.verify && result.Verified != tt.wantVerified {
					t.Errorf("expected verified=%v, got verified=%v", tt.wantVerified, result.Verified)
					if result.VerificationError() != nil {
						t.Logf("verification error: %v", result.VerificationError())
					}
				}

				// Log the result for debugging
				t.Logf("Result: Verified=%v, Raw length=%d, SecretParts=%v",
					result.Verified, len(result.Raw), result.SecretParts)
			}
		})
	}
}
