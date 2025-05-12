package databricks

type ResourceType string

func (r ResourceType) String() string {
	return string(r)
}

const (
	CurrentUser      ResourceType = "User"
	TokensInfo       ResourceType = "Token"
	TokenPermissions ResourceType = "Token Permission"
	Repositories     ResourceType = "Repository"
	GitCredentials   ResourceType = "Git Credential"
	Jobs             ResourceType = "Job"
	Clusters         ResourceType = "Cluster"
	Groups           ResourceType = "Group"
	Users            ResourceType = "Member"
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

type Permissions struct {
	PermissionLevels []struct {
		Description     string `json:"description"`
		PermissionLevel string `json:"permission_level"`
	} `json:"permission_levels"`
}

type ReposResponse struct {
	Repositories []struct {
		ID       string `json:"id"`
		Path     string `json:"path"`
		Provider string `json:"provider"`
		URL      string `json:"url"`
	} `json:"repos"`
}

type GitCreds struct {
	Credentials []struct {
		ID       string `json:"credentials_id"`
		UserName string `json:"git_username"`
		Provider string `json:"git_provider"`
	} `json:"credentials"`
}

type JobsResponse struct {
	Jobs []struct {
		ID          string `json:"job_id"`
		Name        string `json:"name"`
		Description string `json:"description"`
	} `json:"jobs"`
}

type ClustersResponse struct {
	Clusters []struct {
		ID        string `json:"cluster_id"`
		Name      string `json:"cluster_name"`
		CreatedBy string `json:"creator_user_name"`
	} `json:"clusters"`
}

type GroupsResponse struct {
	Resources []struct {
		ID   string `json:"id"`
		Name string `json:"displayName"`
		// TODO: capture members if needed
	} `json:"Resources"`
}

type UsersResponse struct {
	Resources []struct {
		ID       string `json:"id"`
		UserName string `json:"userName"`
		Active   bool   `json:"active"`
	} `json:"Resources"`
}
