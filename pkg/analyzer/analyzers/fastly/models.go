package fastly

import "sync"

const (
	// types
	TypeUserToken         string = "User Token"
	TypeAutomationToken   string = "Automation Token"
	TypeService           string = "Service"
	TypeSvcVersion        string = "Service Version"
	TypeSvcVersionACL     string = "Service Version ACL"
	TypeSvcVersionDict    string = "Service Version Dictionary"
	TypeSvcVersionBackend string = "Service Version Backend"
)

type SecretInfo struct {
	mu sync.RWMutex

	UserInfo  User
	TokenInfo SelfToken
	Resources []FastlyResource
}

type FastlyResource struct {
	ID       string
	Name     string
	Type     string
	Metadata map[string]string
	Parent   *FastlyResource
}

// AppendResource append resource to secret info resource list
func (s *SecretInfo) appendResource(resource FastlyResource) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.Resources = append(s.Resources, resource)
}

// listResourceByType returns a list of resources matching the given type.
func (s *SecretInfo) listResourceByType(resourceType string) []FastlyResource {
	s.mu.RLock()
	defer s.mu.RUnlock()

	resources := make([]FastlyResource, 0, len(s.Resources))
	for _, resource := range s.Resources {
		if resource.Type == resourceType {
			resources = append(resources, resource)
		}
	}

	return resources
}

// getResourceByID get a single resource by ID if found
func (s *SecretInfo) getResourceByID(id string) *FastlyResource {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, resource := range s.Resources {
		if resource.ID == id {
			return &resource
		}
	}

	return nil
}

// API Response models

// User is /current_user API Response
type User struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Login        string `json:"login"`
	Role         string `json:"role"`
	LastActiveAt string `json:"last_active_at"`
}

// SelfToken is /tokens/self API Response
type SelfToken struct {
	ID         string   `json:"id"`
	UserID     string   `json:"user_id"`
	Name       string   `json:"name"`
	LastUsedAt string   `json:"last_used_at"`
	ExpiresAt  string   `json:"expires_at"`
	Scope      string   `json:"scope"`
	Scopes     []string `json:"scopes"`
	Services   []string `json:"services"`
}

// hasGlobalScope returns true if any global scope is assigned to the token
func (t SelfToken) hasGlobalScope() bool {
	for _, scope := range t.Scopes {
		if scope == PermissionStrings[Global] || scope == PermissionStrings[GlobalRead] {
			return true
		}
	}

	return false
}

// TokenData is /automation-tokens API Response
type TokenData struct {
	Data []Token `json:"data"`
}

// Token is /tokens API Response
type Token struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Scope     string `json:"scope"`
	Role      string `json:"role"`
	ExpiresAt string `json:"expires_at"`
}

// Service is /service API Response
type Service struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
}

// Version is /service/<id>/version API Response
type Version struct {
	Number    int    `json:"number"`
	Active    bool   `json:"active"`
	Deployed  bool   `json:"deployed"`
	ServiceID string `json:"service_id"`
}

// ACL is /service/<id>/version/<number>/acl API Response
type ACL struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Dictionary is the /service/<id>/version/<number>/dictionary API Response
type Dictionary struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Backend is the /service/<id>/version/<number>/backend API Response
type Backend struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	Port    string `json:"port"`
}
