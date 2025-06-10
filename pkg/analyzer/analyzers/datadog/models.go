package datadog

import "sync"

// Resource type constants for consistent usage
const (
	ResourceTypeValidate    = "Validate"
	ResourceTypeCurrentUser = "Current User"
	ResourceTypeDashboard   = "Dashboard"
	ResourceTypeMonitor     = "Monitor"
)

// Permission represents a permission granted to an API key
type Permission struct {
	Name        string
	Title       string
	Description string
	MetaData    map[string]string
}

// SecretInfo holds all information gathered about a Datadog API key
type SecretInfo struct {
	User        User
	Permissions []Permission

	mu        sync.RWMutex
	Resources []Resource
}

// User is the information about the user to whom the token belongs
type User struct {
	Id    string
	Name  string
	Email string
}

// Resource represents a Datadog resource
type Resource struct {
	ID       string
	Name     string
	Type     string
	MetaData map[string]string
}

// API response structures
type currentUserResponse struct {
	Data struct {
		Id         string `json:"id"`
		Attributes struct {
			Name  string `json:"name"`
			Email string `json:"email"`
		} `json:"attributes"`
	} `json:"data"`
}

type dashboardResponse struct {
	Dashboards []DashboardItem `json:"dashboards"`
}

type DashboardItem struct {
	ID           string  `json:"id"`
	Title        string  `json:"title"`
	URL          string  `json:"url"`
	IsReadOnly   bool    `json:"is_read_only"`
	CreatedAt    string  `json:"created_at"`
	ModifiedAt   string  `json:"modified_at"`
	AuthorHandle string  `json:"author_handle"`
	Description  *string `json:"description"`
	LayoutType   string  `json:"layout_type"`
	DeletedAt    *string `json:"deleted_at"`
}

type monitorResponse []struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

// appendResource adds a resource to secret info resources list
func (s *SecretInfo) appendResource(resource Resource) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.Resources = append(s.Resources, resource)
}
