package detectors

// AccountFilter implements account-based filtering functionality that detectors can embed
// to gain allow and deny list capabilities for account IDs.
type AccountFilter struct {
	allowedAccounts map[string]struct{}
	deniedAccounts  map[string]struct{}
}

// SetAllowedAccounts configures the allowed account IDs.
// If set, only accounts in this list will be verified.
func (a *AccountFilter) SetAllowedAccounts(accountIDs []string) {
	if len(accountIDs) == 0 {
		a.allowedAccounts = nil
		return
	}

	accounts := make(map[string]struct{}, len(accountIDs))
	for _, accountID := range accountIDs {
		accounts[accountID] = struct{}{}
	}
	a.allowedAccounts = accounts
}

// SetDeniedAccounts configures the denied account IDs.
// Accounts in this list will never be verified.
func (a *AccountFilter) SetDeniedAccounts(accountIDs []string) {
	if len(accountIDs) == 0 {
		a.deniedAccounts = nil
		return
	}

	accounts := make(map[string]struct{}, len(accountIDs))
	for _, accountID := range accountIDs {
		accounts[accountID] = struct{}{}
	}
	a.deniedAccounts = accounts
}

// ShouldSkipAccount checks if an account ID should be skipped for verification
// based on allow and deny lists.
//
// Precedence: deny list > allow list (if account is in both, it's denied)
func (a *AccountFilter) ShouldSkipAccount(accountID string) bool {
	// Check deny list first - takes precedence
	if len(a.deniedAccounts) > 0 {
		if _, isDenied := a.deniedAccounts[accountID]; isDenied {
			return true
		}
	}

	// Check allow list - if populated, account must be in it
	if len(a.allowedAccounts) > 0 {
		if _, isAllowed := a.allowedAccounts[accountID]; !isAllowed {
			return true
		}
	}

	// Account is allowed for verification
	return false
}

// IsInDenyList checks if an account ID is in the deny list
func (a *AccountFilter) IsInDenyList(accountID string) bool {
	if len(a.deniedAccounts) == 0 {
		return false
	}
	_, isDenied := a.deniedAccounts[accountID]
	return isDenied
}

// IsInAllowList checks if an account ID is in the allow list
func (a *AccountFilter) IsInAllowList(accountID string) bool {
	if len(a.allowedAccounts) == 0 {
		return false
	}
	_, isAllowed := a.allowedAccounts[accountID]
	return isAllowed
}
