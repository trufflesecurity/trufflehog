package databricks

type ResourceType string

func (r ResourceType) String() string {
	return string(r)
}

const (
	CurrentUser ResourceType = "User"
	TokensInfo  ResourceType = "Token"
)

type SecretInfo struct {
	UserInfo              User
	TokenPermissionLevels []string
	Tokens                []Token
	Resources             []DataBricksResource
}

type User struct {
	ID           string
	UserName     string
	PrimaryEmail string
}

type Token struct {
	ID          string
	Name        string
	ExpiryTime  string
	CreatedBy   string
	LastUsedDay string
}

type DataBricksResource struct {
	ID       string
	Name     string
	Type     string
	Metadata map[string]string
}

// API response models

type CurrentUserInfo struct {
	ID       string `json:"id"`
	UserName string `json:"userName"`
	Emails   []struct {
		Display string `json:"display"`
		Value   string `json:"value"`
		Primary bool   `json:"primary"`
	} `json:"emails"`
}

type Tokens struct {
	TokensInfo []struct {
		ID          string `json:"token_id"`
		Name        string `json:"comment"`
		ExpiryTime  int    `json:"expiry_time"`
		LastUsedDay int    `json:"last_used_day"`
		CreatedBy   string `json:"created_by_username"`
	} `json:"token_infos"`
}
