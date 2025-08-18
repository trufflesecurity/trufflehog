package access_keys

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestAWS_Pattern(t *testing.T) {
	d := scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "valid pattern",
			input: `
				aws credentials{
					id: ABIAS9L8MS5IPHTZPPUQ
					secret: .v2QPKHl7LcdVYsjaR4LgQiZ1zw3MAnMyiondXC63;
				}
			`,
			want: []string{"ABIAS9L8MS5IPHTZPPUQ:v2QPKHl7LcdVYsjaR4LgQiZ1zw3MAnMyiondXC63"},
		},
		{
			name: "valid pattern - xml",
			input: `
				<com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
  					<scope>GLOBAL</scope>
  					<id>{AKIAWGXZ9OPDOWUJMZGI}</id>
  					<secret>{AQAAABAAA .v2QPKHl7LcdVYsjaR4LgQiZ1zw3MAnMyiondXC63;}</secret>
  					<description>configuration for production</description>
					<creationDate>2023-05-18T14:32:10Z</creationDate>
  					<owner>jenkins-admin</owner>
				</com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
			`,
			want: []string{"AKIAWGXZ9OPDOWUJMZGI:v2QPKHl7LcdVYsjaR4LgQiZ1zw3MAnMyiondXC63"},
		},
		{
			name: "invalid pattern",
			input: `
				aws credentials{
					id: AKIAs9L8MS5iPHTZPPUQ
					secret: $YenOG.PKHl7LcdVYsjaR4LgQiZ1zw3MAnMyiondXC63;
				}
			`,
			want: nil,
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

func TestAWS_shouldSkipAccountVerification(t *testing.T) {
	testCases := []struct {
		name               string
		scanner            scanner
		accountID          string
		expectedShouldSkip bool
		expectedReason     string
	}{
		{
			name: "no filtering configured - should not skip",
			scanner: scanner{
				allowedAccounts: map[string]struct{}{},
				deniedAccounts:  map[string]struct{}{},
			},
			accountID:          "123456789012",
			expectedShouldSkip: false,
			expectedReason:     "",
		},
		{
			name: "account in deny list - should skip",
			scanner: scanner{
				allowedAccounts: map[string]struct{}{},
				deniedAccounts:  map[string]struct{}{"123456789012": {}},
			},
			accountID:          "123456789012",
			expectedShouldSkip: true,
			expectedReason:     "Account ID is in the deny list for verification",
		},
		{
			name: "account not in allow list - should skip",
			scanner: scanner{
				allowedAccounts: map[string]struct{}{"999888777666": {}},
				deniedAccounts:  map[string]struct{}{},
			},
			accountID:          "123456789012",
			expectedShouldSkip: true,
			expectedReason:     "Account ID is not in the allow list for verification",
		},
		{
			name: "account in allow list - should not skip",
			scanner: scanner{
				allowedAccounts: map[string]struct{}{"123456789012": {}},
				deniedAccounts:  map[string]struct{}{},
			},
			accountID:          "123456789012",
			expectedShouldSkip: false,
			expectedReason:     "",
		},
		{
			name: "account in both allow and deny list - deny takes precedence",
			scanner: scanner{
				allowedAccounts: map[string]struct{}{"123456789012": {}},
				deniedAccounts:  map[string]struct{}{"123456789012": {}},
			},
			accountID:          "123456789012",
			expectedShouldSkip: true,
			expectedReason:     "Account ID is in the deny list for verification",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			shouldSkip, reason := tc.scanner.shouldSkipAccountVerification(tc.accountID)

			if shouldSkip != tc.expectedShouldSkip {
				t.Errorf("Expected shouldSkip=%v, got shouldSkip=%v", tc.expectedShouldSkip, shouldSkip)
			}

			if reason != tc.expectedReason {
				t.Errorf("Expected reason=%q, got reason=%q", tc.expectedReason, reason)
			}
		})
	}
}

func TestAWS_WithAllowedAccounts(t *testing.T) {
	accounts := []string{"123456789012", "999888777666"}
	s := New(WithAllowedAccounts(accounts))

	// Test that allowed accounts are properly configured
	shouldSkip, reason := s.shouldSkipAccountVerification("123456789012")
	require.False(t, shouldSkip)
	require.Empty(t, reason)

	// Test that non-allowed accounts are skipped
	shouldSkip, reason = s.shouldSkipAccountVerification("111222333444")
	require.True(t, shouldSkip)
	require.Equal(t, "Account ID is not in the allow list for verification", reason)
}

func TestAWS_WithDeniedAccounts(t *testing.T) {
	accounts := []string{"123456789012", "999888777666"}
	s := New(WithDeniedAccounts(accounts))

	// Test that denied accounts are properly skipped
	shouldSkip, reason := s.shouldSkipAccountVerification("123456789012")
	require.True(t, shouldSkip)
	require.Equal(t, "Account ID is in the deny list for verification", reason)

	// Test that non-denied accounts are not skipped
	shouldSkip, reason = s.shouldSkipAccountVerification("111222333444")
	require.False(t, shouldSkip)
	require.Empty(t, reason)
}
