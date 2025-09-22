package detectors

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEmbeddedAccountFilter(t *testing.T) {
	type Scanner struct{ AccountFilter }

	t.Run("no filtering configured - should not skip", func(t *testing.T) {
		var s Scanner // Fresh instance for this test

		shouldSkip := s.ShouldSkipAccount("test-account")
		assert.False(t, shouldSkip)
		assert.False(t, s.IsInDenyList("test-account"))
		assert.False(t, s.IsInAllowList("test-account"))
	})

	t.Run("allowed accounts only", func(t *testing.T) {
		var s Scanner // Fresh instance for this test
		s.SetAllowedAccounts([]string{"allowed-account-1", "allowed-account-2"})

		// Account in allow list - should not skip
		shouldSkip := s.ShouldSkipAccount("allowed-account-1")
		assert.False(t, shouldSkip)
		assert.True(t, s.IsInAllowList("allowed-account-1"))

		// Account not in allow list - should skip
		shouldSkip = s.ShouldSkipAccount("other-account")
		assert.True(t, shouldSkip)
		assert.False(t, s.IsInAllowList("other-account"))
	})

	t.Run("denied accounts only", func(t *testing.T) {
		var s Scanner // Fresh instance for this test
		s.SetDeniedAccounts([]string{"denied-account-1", "denied-account-2"})

		// Account in deny list - should skip
		shouldSkip := s.ShouldSkipAccount("denied-account-1")
		assert.True(t, shouldSkip)
		assert.True(t, s.IsInDenyList("denied-account-1"))

		// Account not in deny list - should not skip (no allow list restrictions)
		shouldSkip = s.ShouldSkipAccount("other-account")
		assert.False(t, shouldSkip)
		assert.False(t, s.IsInDenyList("other-account"))
	})

	t.Run("deny list takes precedence over allow list", func(t *testing.T) {
		var s Scanner // Fresh instance for this test
		s.SetAllowedAccounts([]string{"conflicted-account", "allowed-only-account"})
		s.SetDeniedAccounts([]string{"conflicted-account"}) // Same account in both lists

		// Account is in both allow and deny lists - deny takes precedence
		shouldSkip := s.ShouldSkipAccount("conflicted-account")
		assert.True(t, shouldSkip)
		assert.True(t, s.IsInDenyList("conflicted-account"))
		assert.True(t, s.IsInAllowList("conflicted-account"))

		// Account only in allow list - should not skip
		shouldSkip = s.ShouldSkipAccount("allowed-only-account")
		assert.False(t, shouldSkip)
		assert.False(t, s.IsInDenyList("allowed-only-account"))
		assert.True(t, s.IsInAllowList("allowed-only-account"))
	})

	t.Run("allow list with denied account not in allow list", func(t *testing.T) {
		var s Scanner                                     // Fresh instance for this test
		s.SetAllowedAccounts([]string{"trusted-account"}) // Allow one account
		s.SetDeniedAccounts([]string{"blocked-account"})  // Deny different account

		// Account in deny list (not in allow list) - should skip due to deny list
		shouldSkip := s.ShouldSkipAccount("blocked-account")
		assert.True(t, shouldSkip)
		assert.True(t, s.IsInDenyList("blocked-account"))
		assert.False(t, s.IsInAllowList("blocked-account"))

		// Account in allow list (not in deny list) - should not skip
		shouldSkip = s.ShouldSkipAccount("trusted-account")
		assert.False(t, shouldSkip)
		assert.False(t, s.IsInDenyList("trusted-account"))
		assert.True(t, s.IsInAllowList("trusted-account"))

		// Account in neither list - should skip due to allow list restriction
		shouldSkip = s.ShouldSkipAccount("unknown-account")
		assert.True(t, shouldSkip)
		assert.False(t, s.IsInDenyList("unknown-account"))
		assert.False(t, s.IsInAllowList("unknown-account"))
	})

	t.Run("clearing lists", func(t *testing.T) {
		var s Scanner // Fresh instance for this test
		s.SetAllowedAccounts([]string{"initial-allowed"})
		s.SetDeniedAccounts([]string{"initial-denied"})

		// Verify initial state
		assert.True(t, s.ShouldSkipAccount("random-account")) // Not in allow list
		assert.True(t, s.ShouldSkipAccount("initial-denied")) // In deny list

		// Clear allowed accounts with nil
		s.SetAllowedAccounts(nil)
		assert.False(t, s.ShouldSkipAccount("random-account")) // No allow list restriction
		assert.True(t, s.ShouldSkipAccount("initial-denied"))  // Still in deny list

		// Clear denied accounts with empty slice
		s.SetDeniedAccounts([]string{})
		assert.False(t, s.ShouldSkipAccount("initial-denied"))  // No longer denied
		assert.False(t, s.ShouldSkipAccount("initial-allowed")) // No restrictions
	})
}
