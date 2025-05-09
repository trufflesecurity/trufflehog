package databricks

type ResourceType string

func (r ResourceType) String() string {
	return string(r)
}

const (
	CurrentUser ResourceType = "User"
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

type userEmails struct {
	Display string `json:"display"`
	Value   string `json:"value"`
	Primary bool   `json:"primary"`
}
