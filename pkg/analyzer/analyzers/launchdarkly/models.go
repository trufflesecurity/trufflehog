package launchdarkly

import "sync"

var (
	MetadataKey = "key"

	// resource types
	applicationKey  = "Application"
	repositoryKey   = "Repository"
	projectKey      = "Project"
	environmentKey  = "Environment"
	experimentKey   = "Experiment"
	holdoutsKey     = "Holdout"
	membersKey      = "Member"
	destinationsKey = "Destination"
	templatesKey    = "Templates"
	teamsKey        = "Teams"
	webhooksKey     = "Webhooks"
	featureFlagsKey = "Feature Flags"
)

type SecretInfo struct {
	User        User
	Permissions []string

	mu        sync.RWMutex
	Resources []Resource
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

// policy is a set of statements
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

// appendResource append resource to secret info resources list
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

// hasCustomRoles check if token has any custom roles assigned
func (t Token) hasCustomRoles() bool {
	return len(t.CustomRoles) > 0
}

// hasInlineRole check if token has any inline roles
func (t Token) hasInlineRole() bool {
	return len(t.InlineRole) > 0
}
