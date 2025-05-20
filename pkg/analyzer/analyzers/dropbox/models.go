package dropbox

type scopeConfig struct {
	Scopes map[string]scope `json:"scopes"`
}

type scope struct {
	TestEndpoint  string   `json:"test_endpoint"`
	ImpliedScopes []string `json:"implied_scopes"`
	Actions       []string `json:"actions"`
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

type accountPermission struct {
	Name    string
	Status  PermissionStatus
	Actions []string
}

type secretInfo struct {
	Account     account
	Permissions []accountPermission
}
