package session_keys

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestAWSSessionKey_Pattern(t *testing.T) {
	d := New()
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
					id: ASIABBKK02W42Q3IPSPG
					secret: fkhIiUwQY32Zu9e4a86g9r3WpTzfE1aXljVcgn8O
					session: aSqfp/GTZbJP+tXPNCZ9GoveoM0vgxtlYXdzPQ2uYNMPPgUkt0VT7SoTLasAo7iVqWWREOUC6DEenlcgDEKyzIEgQW5Ju/b9K/Z176uD2HJYCfq/lyowHtt5PvJi7LRuf/urSorGbTcqNUvPi42YP1Ps/4F6He9hQA1io3EAGBC3ICGHXWf2IlvFoTNUyPTqhjnPEKMWZ42jblqNAdD7hLpzNXmmGhdLCjy99XK8+gjHdZHkOeD/FIjRPRZ7Jl0tdwdqFEwzRVCzL2uelMVMd3UaZ+d4I4Kf+J464piO//jxx48Fs/mG3zr5ba9m2S+6gvUZJq4j+0uJ+jf6cG/x2G9XSybqYQRwvxfNquKB4TcKiGVH5+ZbJT4ASkARadwoSPMGfvMPje+X2zAziSzXfsxYfIQKf6iJ9p7VavlDGi+Acr4kwFXW5IfQs4uGk6AVQFsoZK3o1hhLOkuOwWQEWhDQGNLXwJbFqXfELOnUQvM0Z5NUm46bjAAi4g+X9gLPNR/KjzXuuTTaWYrQEjXLb7PxS0sIttAb1w+sTXXtc1kDIsABC6KcsyGlEwji5sLkbkUa=
				}
			`,
			want: []string{"ASIABBKK02W42Q3IPSPG:fkhIiUwQY32Zu9e4a86g9r3WpTzfE1aXljVcgn8O:aSqfp/GTZbJP+tXPNCZ9GoveoM0vgxtlYXdzPQ2uYNMPPgUkt0VT7SoTLasAo7iVqWWREOUC6DEenlcgDEKyzIEgQW5Ju/b9K/Z176uD2HJYCfq/lyowHtt5PvJi7LRuf/urSorGbTcqNUvPi42YP1Ps/4F6He9hQA1io3EAGBC3ICGHXWf2IlvFoTNUyPTqhjnPEKMWZ42jblqNAdD7hLpzNXmmGhdLCjy99XK8+gjHdZHkOeD/FIjRPRZ7Jl0tdwdqFEwzRVCzL2uelMVMd3UaZ+d4I4Kf+J464piO//jxx48Fs/mG3zr5ba9m2S+6gvUZJq4j+0uJ+jf6cG/x2G9XSybqYQRwvxfNquKB4TcKiGVH5+ZbJT4ASkARadwoSPMGfvMPje+X2zAziSzXfsxYfIQKf6iJ9p7VavlDGi+Acr4kwFXW5IfQs4uGk6AVQFsoZK3o1hhLOkuOwWQEWhDQGNLXwJbFqXfELOnUQvM0Z5NUm46bjAAi4g+X9gLPNR/KjzXuuTTaWYrQEjXLb7PxS0sIttAb1w+sTXXtc1kDIsABC6KcsyGlEwji5sLkbkUa="},
		},
		{
			name: "valid pattern - xml",
			input: `
				<com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
  					<scope>GLOBAL</scope>
  					<id>{ASIABBKK02W42Q3IPSPG}</id>
					<secret>{AQAAABAAA fkhIiUwQY32Zu9e4a86g9r3WpTzfE1aXljVcgn8O}</secret>
  					<session>{AQAAABAAA aSqfp/GTZbJP+tXPNCZ9GoveoM0vgxtlYXdzPQ2uYNMPPgUkt0VT7SoTLasAo7iVqWWREOUC6DEenlcgDEKyzIEgQW5Ju/b9K/Z176uD2HJYCfq/lyowHtt5PvJi7LRuf/urSorGbTcqNUvPi42YP1Ps/4F6He9hQA1io3EAGBC3ICGHXWf2IlvFoTNUyPTqhjnPEKMWZ42jblqNAdD7hLpzNXmmGhdLCjy99XK8+gjHdZHkOeD/FIjRPRZ7Jl0tdwdqFEwzRVCzL2uelMVMd3UaZ+d4I4Kf+J464piO//jxx48Fs/mG3zr5ba9m2S+6gvUZJq4j+0uJ+jf6cG/x2G9XSybqYQRwvxfNquKB4TcKiGVH5+ZbJT4ASkARadwoSPMGfvMPje+X2zAziSzXfsxYfIQKf6iJ9p7VavlDGi+Acr4kwFXW5IfQs4uGk6AVQFsoZK3o1hhLOkuOwWQEWhDQGNLXwJbFqXfELOnUQvM0Z5NUm46bjAAi4g+X9gLPNR/KjzXuuTTaWYrQEjXLb7PxS0sIttAb1w+sTXXtc1kDIsABC6KcsyGlEwji5sLkbkUa=}</session>
  					<description>configuration for production</description>
					<creationDate>2023-05-18T14:32:10Z</creationDate>
  					<owner>jenkins-admin</owner>
				</com.cloudbees.plugins.credentials.impl.StringCredentialsImpl>
			`,
			want: []string{"ASIABBKK02W42Q3IPSPG:fkhIiUwQY32Zu9e4a86g9r3WpTzfE1aXljVcgn8O:aSqfp/GTZbJP+tXPNCZ9GoveoM0vgxtlYXdzPQ2uYNMPPgUkt0VT7SoTLasAo7iVqWWREOUC6DEenlcgDEKyzIEgQW5Ju/b9K/Z176uD2HJYCfq/lyowHtt5PvJi7LRuf/urSorGbTcqNUvPi42YP1Ps/4F6He9hQA1io3EAGBC3ICGHXWf2IlvFoTNUyPTqhjnPEKMWZ42jblqNAdD7hLpzNXmmGhdLCjy99XK8+gjHdZHkOeD/FIjRPRZ7Jl0tdwdqFEwzRVCzL2uelMVMd3UaZ+d4I4Kf+J464piO//jxx48Fs/mG3zr5ba9m2S+6gvUZJq4j+0uJ+jf6cG/x2G9XSybqYQRwvxfNquKB4TcKiGVH5+ZbJT4ASkARadwoSPMGfvMPje+X2zAziSzXfsxYfIQKf6iJ9p7VavlDGi+Acr4kwFXW5IfQs4uGk6AVQFsoZK3o1hhLOkuOwWQEWhDQGNLXwJbFqXfELOnUQvM0Z5NUm46bjAAi4g+X9gLPNR/KjzXuuTTaWYrQEjXLb7PxS0sIttAb1w+sTXXtc1kDIsABC6KcsyGlEwji5sLkbkUa="},
		},
		{
			name: "invalid pattern",
			input: `
				aws credentials{
					id: ASIABBKK02W42Q3IPSPG
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

func TestAWSSessionKey_shouldSkipAccountVerification(t *testing.T) {
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

func TestAWSSessionKey_WithAllowedAccounts(t *testing.T) {
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

func TestAWSSessionKey_WithDeniedAccounts(t *testing.T) {
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
