package launchdarkly

import "sync"

var (
	MetadataKey = "key"

	// resource types
	applicationType = "Application"
	repositoryType  = "Repository"
	projectType     = "Project"
	environmentType = "Environment"
	experimentType  = "Expirement"
)

type SecretInfo struct {
	User        User
	Permissions []string
	Resources   []Resource
	// to concurrently read and write
	mu sync.RWMutex
}

// User is the information about the user to whom the token belongs
type User struct {
	AccountID string // account id. It is the owner id of token as well
	MemberID  string
	Name      string
	Role      string // role of caller
	Email     string
	Token     Token
}

// Token is the token details
type Token struct {
	ID             string       // id of the token
	Name           string       // name of the token
	CustomRoles    []CustomRole // custom roles assigned to the token
	InlineRole     []Policy     // any policy statements maybe used in place of a built-in custom role
	Role           string       // role of token
	IsServiceToken bool         // is a service token or not
	APIVersion     int          // default api version assigned to the token
}

// CustomRole is a flexible policies providing fine-grained access control to everything in launch darkly
type CustomRole struct {
	ID                string
	Key               string
	Name              string
	Polices           []Policy
	BasePermission    string
	AssignedToMembers int
	AssignedToTeams   int
}

/*
policy is a set of statements

Jargon:
  - Resource: List of resources
  - NotResources: Except this list of resources
  - Actions: List of actions
  - NotActions: Except this list of actions
  - Effect: Allowed or Denied
*/
type Policy struct {
	Resources    []string
	NotResources []string
	Actions      []string
	NotActions   []string
	Effect       string
}

type Resource struct {
	ID             string
	Name           string
	Permission     string
	Type           string
	ParentResource *Resource
	MetaData       map[string]string
}

// addPermission add a new permission to secret info permissions list.
func (s *SecretInfo) addPermission(perm string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.Permissions = append(s.Permissions, perm)
}

// hasPermission checks if a particular permission exist in secret info permissions list.
func (s *SecretInfo) hasPermission(perm string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, permission := range s.Permissions {
		if permission == perm {
			return true
		}
	}

	return false
}

// appendResources append resource to secret info resources list
func (s *SecretInfo) appendResource(resource Resource) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.Resources = append(s.Resources, resource)
}

// listResourceByType returns a list of resources matching the given type.
func (s *SecretInfo) listResourceByType(resourceType string) []Resource {
	s.mu.RLock()
	defer s.mu.RUnlock()

	resources := make([]Resource, 0, len(s.Resources))
	for _, resource := range s.Resources {
		if resource.Type == resourceType {
			resources = append(resources, resource)
		}
	}

	return resources
}

// getResourceByID returns a copy of the resource matching the given ID, or nil if not found.
func (s *SecretInfo) getResourceByID(id string) *Resource {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, resource := range s.Resources {
		if resource.ID == id {
			// return a copy of the resource to avoid accidently making changes in the actual resource
			copyResource := resource
			return &copyResource
		}
	}

	return nil
}

// hasCustomRoles check if token has any custom roles assigned
func (t Token) hasCustomRoles() bool {
	return len(t.CustomRoles) > 0
}

// hasInlineRole check if token has any inline roles
func (t Token) hasInlineRole() bool {
	return len(t.InlineRole) > 0
}

// isAllowed check if policy allow the statement
func (p Policy) isAllowed() bool {
	return p.Effect == "allow"
}

// setParentResource set parent resource for a resource
func (r Resource) setParentResource(resource, parent *Resource) {
	resource.ParentResource = parent
}

// updateResourceMetadata
func (r Resource) updateResourceMetadata(key, value string) {
	if r.MetaData == nil {
		r.MetaData = make(map[string]string)
	}

	r.MetaData[key] = value
}
