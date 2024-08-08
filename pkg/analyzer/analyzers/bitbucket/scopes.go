package bitbucket

var credential_type_map = map[string]string{
	"repo_access_token":      "Repository Access Token (Can access 1 repository)",
	"project_access_token":   "Project Access Token (Can access all repos in 1 project)",
	"workspace_access_token": "Workspace Access Token (Can access all projects and repos in 1 workspace)",
}

type BitbucketScope struct {
	Name          string   `json:"name"`
	Category      string   `json:"category"`
	ImpliedScopes []string `json:"implied_scopes"`
}

type ByCategoryAndName []BitbucketScope

func (a ByCategoryAndName) Len() int      { return len(a) }
func (a ByCategoryAndName) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a ByCategoryAndName) Less(i, j int) bool {
	categoryOrder := map[string]int{
		"Account":       0,
		"Projects":      1,
		"Repositories":  2,
		"Pull Requests": 3,
		"Webhooks":      4,
		"Pipelines":     5,
		"Runners":       6,
	}
	nameOrder := map[string]int{
		"Read":           0,
		"Write":          1,
		"Admin":          2,
		"Delete":         3,
		"Edit variables": 4,
		"Read and write": 5,
	}

	if categoryOrder[a[i].Category] != categoryOrder[a[j].Category] {
		return categoryOrder[a[i].Category] < categoryOrder[a[j].Category]
	}
	return nameOrder[a[i].Name] < nameOrder[a[j].Name]
}

var oauth_scope_map = map[string]BitbucketScope{
	"repository": {
		Name:     "Read",
		Category: "Repositories",
	},
	"repository:write": {
		Name:          "Write",
		Category:      "Repositories",
		ImpliedScopes: []string{"repository"},
	},
	"repository:admin": {
		Name:     "Admin",
		Category: "Repositories",
	},
	"repository:delete": {
		Name:     "Delete",
		Category: "Repositories",
	},
	"pullrequest": {
		Name:          "Read",
		Category:      "Pull Requests",
		ImpliedScopes: []string{"repository"},
	},
	"pullrequest:write": {
		Name:          "Write",
		Category:      "Pull Requests",
		ImpliedScopes: []string{"pullrequest", "repository", "repository:write"},
	},
	"webhook": {
		Name:     "Read and write",
		Category: "Webhooks",
	},
	"pipeline": {
		Name:     "Read",
		Category: "Pipelines",
	},
	"pipeline:write": {
		Name:          "Write",
		Category:      "Pipelines",
		ImpliedScopes: []string{"pipeline"},
	},
	"pipeline:variable": {
		Name:          "Edit variables",
		Category:      "Pipelines",
		ImpliedScopes: []string{"pipeline", "pipeline:write"},
	},
	"runner": {
		Name:     "Read",
		Category: "Runners",
	},
	"runner:write": {
		Name:          "Write",
		Category:      "Runners",
		ImpliedScopes: []string{"runner"},
	},
	"project": {
		Name:          "Read",
		Category:      "Projects",
		ImpliedScopes: []string{"repository"},
	},
	"project:admin": {
		Name:     "Admin",
		Category: "Projects",
	},
	"account": {
		Name:     "Read",
		Category: "Account",
	},
}
