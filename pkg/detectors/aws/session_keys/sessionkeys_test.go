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

func TestAWSSessionKey_WithAllowedAccounts(t *testing.T) {
	accounts := []string{"123456789012", "999888777666"}
	s := New(WithAllowedAccounts(accounts))

	// Test that allowed accounts are properly configured
	shouldSkip := s.ShouldSkipAccount("123456789012")
	require.False(t, shouldSkip)
	require.True(t, s.IsInAllowList("123456789012"))

	// Test that non-allowed accounts are skipped
	shouldSkip = s.ShouldSkipAccount("111222333444")
	require.True(t, shouldSkip)
	require.False(t, s.IsInAllowList("111222333444"))
}

func TestAWSSessionKey_WithDeniedAccounts(t *testing.T) {
	accounts := []string{"123456789012", "999888777666"}
	s := New(WithDeniedAccounts(accounts))

	// Test that denied accounts are properly skipped
	shouldSkip := s.ShouldSkipAccount("123456789012")
	require.True(t, shouldSkip)
	require.True(t, s.IsInDenyList("123456789012"))

	// Test that non-denied accounts are not skipped
	shouldSkip = s.ShouldSkipAccount("111222333444")
	require.False(t, shouldSkip)
	require.False(t, s.IsInDenyList("111222333444"))
}
