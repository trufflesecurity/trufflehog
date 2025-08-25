package access_keys

import (
	"context"
	"fmt"
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

func TestAWS_WithAllowedAccounts(t *testing.T) {
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

func TestAWS_WithDeniedAccounts(t *testing.T) {
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

func TestAWS_CanaryTokenFiltering(t *testing.T) {
	// Using known canary token from integration tests
	canaryAccessKeyID := "AKIASP2TPHJSQH3FJRUX" // Account ID: 171436882533
	canarySecret := "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	testData := []byte(fmt.Sprintf("%s:%s", canaryAccessKeyID, canarySecret))

	t.Run("debug canary detection", func(t *testing.T) {
		// First, let's test basic canary detection without verification
		s := New()

		results, err := s.FromData(context.Background(), false, testData) // verify = false
		require.NoError(t, err)
		require.Len(t, results, 1)

		result := results[0]
		t.Logf("Result without verification - Verified: %v, Account: %s, IsCanary: %s, Message: %s",
			result.Verified, result.ExtraData["account"], result.ExtraData["is_canary"], result.ExtraData["message"])

		// Should detect as canary but not verify (since verify=false)
		require.False(t, result.Verified)
		require.Equal(t, "171436882533", result.ExtraData["account"])
		require.Equal(t, "true", result.ExtraData["is_canary"])
		require.Contains(t, result.ExtraData["message"], "canarytokens.org")
	})

	t.Run("canary token with allow list - account not allowed", func(t *testing.T) {
		// Configure scanner with allow list that excludes the canary account
		s := New(WithAllowedAccounts([]string{"123456789012", "999888777666"}))

		results, err := s.FromData(context.Background(), true, testData)
		require.NoError(t, err)
		require.Len(t, results, 1)

		result := results[0]
		// Should detect the canary token but not verify it due to filtering
		require.False(t, result.Verified)
		require.NotNil(t, result.VerificationError())
		require.Contains(t, result.VerificationError().Error(), "not in the allow list")
		require.Equal(t, "171436882533", result.ExtraData["account"])
		require.Equal(t, "true", result.ExtraData["is_canary"])
	})

	t.Run("canary token with deny list - account denied", func(t *testing.T) {
		// Configure scanner with deny list that includes the canary account
		s := New(WithDeniedAccounts([]string{"171436882533", "123456789012"}))

		results, err := s.FromData(context.Background(), true, testData)
		require.NoError(t, err)
		require.Len(t, results, 1)

		result := results[0]
		// Should detect the canary token but not verify it due to filtering
		require.False(t, result.Verified)
		require.NotNil(t, result.VerificationError())
		require.Contains(t, result.VerificationError().Error(), "in the deny list")
		require.Equal(t, "171436882533", result.ExtraData["account"])
		require.Equal(t, "true", result.ExtraData["is_canary"])
	})

	t.Run("precedence test - deny list takes precedence over allow list", func(t *testing.T) {
		// Configure scanner where canary account is in both allow and deny lists
		s := New(
			WithAllowedAccounts([]string{"171436882533", "123456789012"}),
			WithDeniedAccounts([]string{"171436882533"}),
		)

		results, err := s.FromData(context.Background(), true, testData)
		require.NoError(t, err)
		require.Len(t, results, 1)

		result := results[0]
		// Should detect the canary token but not verify it since deny takes precedence
		require.False(t, result.Verified)
		require.NotNil(t, result.VerificationError())
		require.Contains(t, result.VerificationError().Error(), "in the deny list")
		require.Equal(t, "171436882533", result.ExtraData["account"])
		require.Equal(t, "true", result.ExtraData["is_canary"])
	})
}
