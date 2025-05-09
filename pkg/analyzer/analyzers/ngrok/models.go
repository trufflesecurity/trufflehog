package ngrok

type apiKey struct {
	ID          string `json:"id"`
	URI         string `json:"uri"`
	Description string `json:"description"`
	Metadata    string `json:"metadata"`
	OwnerID     string `json:"owner_id"`
	CreatedAt   string `json:"created_at"`
}

type authtoken struct {
	ID          string   `json:"id"`
	URI         string   `json:"uri"`
	Description string   `json:"description"`
	Metadata    string   `json:"metadata"`
	ACL         []string `json:"acl"`
	OwnerID     string   `json:"owner_id"`
	CreatedAt   string   `json:"created_at"`
}

type sshCredential struct {
	ID          string   `json:"id"`
	URI         string   `json:"uri"`
	Description string   `json:"description"`
	PublicKey   string   `json:"public_key"`
	Metadata    string   `json:"metadata"`
	ACL         []string `json:"acl"`
	OwnerID     string   `json:"owner_id"`
	CreatedAt   string   `json:"created_at"`
}

type domain struct {
	ID        string `json:"id"`
	URI       string `json:"uri"`
	Domain    string `json:"domain"`
	Metadata  string `json:"metadata"`
	CreatedAt string `json:"created_at"`
}

type endpoint struct {
	ID        string   `json:"id"`
	Region    string   `json:"region"`
	Host      string   `json:"host"`
	Port      int64    `json:"port"`
	PublicURL string   `json:"public_url"`
	Proto     string   `json:"proto"`
	Hostport  string   `json:"hostport"`
	Type      string   `json:"type"`
	Bindings  []string `json:"bindings"`
	URI       string   `json:"uri"`
	Metadata  string   `json:"metadata"`
	CreatedAt string   `json:"created_at"`
	UpdatedAt string   `json:"updated_at"`
}

type botUser struct {
	ID        string `json:"id"`
	URI       string `json:"uri"`
	Name      string `json:"name"`
	Active    bool   `json:"active"`
	CreatedAt string `json:"created_at"`
}

type user struct {
	ID string `json:"id"`
}

type paginatedResponse struct {
	NextPageURI    string          `json:"next_page_uri"`
	APIKeys        []apiKey        `json:"keys,omitempty"`
	Authtokens     []authtoken     `json:"credentials,omitempty"`
	SSHCredentials []sshCredential `json:"ssh_credentials,omitempty"`
	Domains        []domain        `json:"reserved_domains,omitempty"`
	Endpoints      []endpoint      `json:"endpoints,omitempty"`
	BotUsers       []botUser       `json:"bot_users,omitempty"`
}

type secretInfo struct {
	Users          []user
	BotUsers       []botUser
	APIKeys        []apiKey
	Authtokens     []authtoken
	SSHCredentials []sshCredential
	Domains        []domain
	Endpoints      []endpoint
	AccountType    AccountType
}
