package dropbox

type scopeConfig struct {
	Scopes []scope `json:"scopes"`
}

type scope struct {
	Name          string   `json:"name"`
	TestEndpoint  string   `json:"test_endpoint"`
	ImpliedScopes []string `json:"implied_scopes"`
}

type account struct {
	AccountID     string      `json:"account_id"`
	Name          name        `json:"name"`
	Email         string      `json:"email"`
	EmailVerified bool        `json:"email_verified"`
	Disabled      bool        `json:"disabled"`
	Country       string      `json:"country"`
	AccountType   accountType `json:"account_type"`
}

type accountType struct {
	Tag string `json:".tag"`
}

type name struct {
	GivenName string `json:"given_name"`
	Surname   string `json:"surname"`
}

type secretInfo struct {
	Account     account
	Permissions map[string]PermissionStatus
}
