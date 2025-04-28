package netlify

import "sync"

type ResourceType string

func (r ResourceType) String() string {
	return string(r)
}

const (
	CurrentUser ResourceType = "User"
	Token       ResourceType = "Token"
	Site        ResourceType = "Site"
	SiteFile    ResourceType = "Site File"
	SiteEnvVar  ResourceType = "Site Env Variable"
)

type SecretInfo struct {
	mu sync.RWMutex

	UserInfo  User
	Resources []NetlifyResource
}

func (s *SecretInfo) appendResource(resource NetlifyResource) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.Resources = append(s.Resources, resource)
}

// listResourceByType returns a list of resources matching the given type.
func (s *SecretInfo) listResourceByType(resourceType ResourceType) []NetlifyResource {
	s.mu.RLock()
	defer s.mu.RUnlock()

	resources := make([]NetlifyResource, 0, len(s.Resources))
	for _, resource := range s.Resources {
		if resource.Type == resourceType.String() {
			resources = append(resources, resource)
		}
	}

	return resources
}

type User struct {
	ID        string `json:"id"`
	Name      string `json:"full_name"`
	Email     string `json:"email"`
	AccountID string `json:"account_id"`
	LastLogin string `json:"last_login"`
}

type NetlifyResource struct {
	ID       string
	Name     string
	Type     string
	Metadata map[string]string
	Parent   *NetlifyResource
}

type token struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Personal  bool   `json:"personal"`
	ExpiresAt string `json:"expires_at"`
}

type site struct {
	SiteID   string `json:"site_id"`
	Name     string `json:"name"`
	Url      string `json:"url"`
	AdminUrl string `json:"admin_url"`
	RepoUrl  string `json:"repo_url"`
}

type file struct {
	ID       string `json:"id"`
	Path     string `json:"path"`
	MimeType string `json:"mime_type"`
}

type envVariable struct {
	Key    string   `json:"key"`
	Scopes []string `json:"scopes"`
	Values []struct {
		ID    string `json:"id"`
		Value string `json:"value"`
	} `json:"values"`
}
