package dropbox

type scopeConfig struct {
	AccountScopes       []scope `json:"account_info_scopes"`
	FilesMetadataScopes []scope `json:"files_metadata_scopes"`
	FilesContentScopes  []scope `json:"files_content_scopes"`
	SharingScopes       []scope `json:"sharing_scopes"`
	FileRequestsScopes  []scope `json:"file_requests_scopes"`
	ContactsScopes      []scope `json:"contacts_scopes"`
	OpenIDScopes        []scope `json:"openid_scopes"`
}

type scope struct {
	Name          string   `json:"name"`
	TestEndpoint  string   `json:"test_endpoint"`
	ImpliedScopes []string `json:"impliedScopes"`
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

type resource struct {
	Name        string
	DisplayName string
	Permissions map[string]PermissionStatus
}

type secretInfo struct {
	Account   account
	Resources []resource
}
