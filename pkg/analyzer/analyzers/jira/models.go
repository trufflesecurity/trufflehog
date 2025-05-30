package jira

import "sync"

const (
	ResourceTypeProject = "Project"
	ResourceTypeBoard   = "Board"
	ResourceTypeGroup   = "Group"
)

type SecretInfo struct {
	mu sync.RWMutex

	UserInfo    JiraUser
	Permissions []string
	// TokenInfo   SelfToken
	Resources []JiraResource
}

// JiraUser represents the response from /myself API
type JiraUser struct {
	AccountID    string `json:"accountId"`
	AccountType  string `json:"accountType"`
	DisplayName  string `json:"displayName"`
	EmailAddress string `json:"emailAddress"`
	Active       bool   `json:"active"`
	TimeZone     string `json:"timeZone"`
	Locale       string `json:"locale"`
	Self         string `json:"self"`
}

type JiraResource struct {
	ID       string
	Name     string
	Type     string
	Metadata map[string]string
	Parent   *JiraResource
}

// AppendResource append resource to secret info resource list
func (s *SecretInfo) appendResource(resource JiraResource) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.Resources = append(s.Resources, resource)
}

// listResourceByType returns a list of resources matching the given type.
func (s *SecretInfo) listResourceByType(resourceType string) []JiraResource {
	s.mu.RLock()
	defer s.mu.RUnlock()

	resources := make([]JiraResource, 0, len(s.Resources))
	for _, resource := range s.Resources {
		if resource.Type == resourceType {
			resources = append(resources, resource)
		}
	}

	return resources
}

// API Response models

type JiraPermissionsResponse struct {
	Permissions map[string]JiraPermission `json:"permissions"`
}

type JiraPermission struct {
	ID             string `json:"id"`
	Key            string `json:"key"`
	Name           string `json:"name"`
	Type           string `json:"type"`
	Description    string `json:"description"`
	HavePermission bool   `json:"havePermission"`
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

type ProjectSearchResponse struct {
	MaxResults int           `json:"maxResults"`
	Total      int           `json:"total"`
	IsLast     bool          `json:"isLast"`
	Values     []JiraProject `json:"values"`
}

type JiraProject struct {
	ID             string `json:"id"`
	Key            string `json:"key"`
	Name           string `json:"name"`
	ProjectTypeKey string `json:"projectTypeKey"`
	IsPrivate      bool   `json:"isPrivate"`
	UUID           string `json:"uuid"`
}

type JiraIssue struct {
	Issues []struct {
		ID     string `json:"id"`
		Key    string `json:"key"`
		Fields struct {
			Summary string `json:"summary"`
			Status  struct {
				Name string `json:"name"`
			} `json:"status"`
			IssueType struct {
				Name string `json:"name"`
			} `json:"issuetype"`
		} `json:"fields"`
	} `json:"issues"`
}

type JiraBoard struct {
	Values []struct {
		ID        int    `json:"id"`
		Name      string `json:"name"`
		Type      string `json:"type"`
		Self      string `json:"self"`
		IsPrivate bool   `json:"isPrivate"`
		Location  struct {
			ProjectID      int    `json:"projectId"`
			DisplayName    string `json:"displayName"`
			ProjectName    string `json:"projectName"`
			ProjectKey     string `json:"projectKey"`
			ProjectTypeKey string `json:"projectTypeKey"`
			AvatarURI      string `json:"avatarURI"`
			Name           string `json:"name"`
		} `json:"location"`
	} `json:"values"`
}

type JiraGroup struct {
	Total  int `json:"total"`
	Groups []struct {
		Name    string `json:"name"`
		HTML    string `json:"html"`
		GroupID string `json:"groupId"`
		Labels  []struct {
			Text  string `json:"text"`
			Title string `json:"title"`
			Type  string `json:"type"`
		} `json:"labels"`
	} `json:"groups"`
}

type AuditRecord struct {
	Offset  int `json:"offset"`
	Limit   int `json:"limit"`
	Total   int `json:"total"`
	Records []struct {
		ID            int    `json:"id"`
		Summary       string `json:"summary"`
		Created       string `json:"created"`
		Category      string `json:"category"`
		EventSource   string `json:"eventSource"`
		RemoteAddress string `json:"remoteAddress,omitempty"`
		AuthorKey     string `json:"authorKey,omitempty"`
		AuthorAccount string `json:"authorAccountId,omitempty"`

		ObjectItem struct {
			ID         string `json:"id,omitempty"`
			Name       string `json:"name"`
			TypeName   string `json:"typeName"`
			ParentID   string `json:"parentId,omitempty"`
			ParentName string `json:"parentName,omitempty"`
		} `json:"objectItem"`

		AssociatedItems []struct {
			ID         string `json:"id"`
			Name       string `json:"name"`
			TypeName   string `json:"typeName"`
			ParentID   string `json:"parentId"`
			ParentName string `json:"parentName"`
		} `json:"associatedItems"`

		ChangedValues []struct {
			FieldName string `json:"fieldName"`
			ChangedTo string `json:"changedTo"`
		} `json:"changedValues"`
	} `json:"records"`
}
