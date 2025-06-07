package common

var scopeToPermissions = map[string][]string{
	// Basic Scopes
	"data.records:read": {
		"List records",
		"Get record",
	},
	"data.records:write": {
		"Create records",
		"Update record",
		"Update multiple records",
		"Delete record",
		"Delete multiple records",
		"Sync CSV data",
	},
	"data.recordComments:read": {
		"List comments",
	},
	"data.recordComments:write": {
		"Create comment",
		"Delete comment",
		"Update comment",
	},
	"schema.bases:read": {
		"List bases",
		"Get base schema",
	},
	"schema.bases:write": {
		"Create base",
		"Create table",
		"Update table",
		"Create field",
		"Update field",
		"Sync CSV data",
	},
	"webhook:manage": {
		"List webhooks",
		"Create a webhook",
		"Delete a webhook",
		"Enable/disable webhook notifications",
		"Refresh a webhook",
	},
	"block:manage": {
		"Create new releases and submissions for custom extensions",
	},
	"user.email:read": {
		"See the user's email address",
	},

	// Enterprise scopes
	"enterprise.groups:read": {
		"Get user group",
	},
	"workspacesAndBases:read": {
		"Get base collaborators",
		"List block installations",
		"Get interface",
		"List views",
		"Get view metadata",
		"Get workspace collaborators",
	},
	"workspacesAndBases:write": {
		"Delete block installation",
		"Manage block installation",
		"Add base collaborator",
		"Delete base collaborator",
		"Update collaborator base permission",
		"Add interface collaborator",
		"Delete interface collaborator",
		"Update interface collaborator",
		"Delete interface invite",
		"Delete base invite",
		"Delete view",
		"Add workspace collaborator",
		"Delete workspace collaborator",
		"Update workspace collaborator",
		"Delete workspace invite",
		"Update workspace restrictions",
	},
	"workspacesAndBases.shares:manage": {
		"List shares",
		"Delete share",
		"Manage share",
	},
	"enterprise.scim.usersAndGroups:manage": {
		"List groups",
		"Create group",
		"Delete group",
		"Get group",
		"Patch group",
		"Put group",
		"List users",
		"Create user",
		"Delete user",
		"Get user",
		"Patch user",
		"Put user",
	},
	"enterprise.auditLogs:read": {
		"Audit log events",
		"List audit log requests",
		"Create audit log request",
		"Get audit log request",
	},
	"enterprise.changeEvents:read": {
		"Change events",
	},
	"enterprise.exports:manage": {
		"List eDiscovery exports",
		"Create eDiscovery export",
		"Get eDiscovery export",
	},
	"enterprise.account:read": {
		"Get enterprise",
	},
	"enterprise.account:write": {
		"Create descendant enterprise",
	},
	"enterprise.user:read": {
		"Get users by id or email",
		"Get user by id",
	},
	"enterprise.user:write": {
		"Delete users by email",
		"Manage user batched",
		"Manage user membership",
		"Grant admin access",
		"Revoke admin access",
		"Delete user by id",
		"Manage user",
		"Logout user",
		"Remove user from enterprise",
	},
	"enterprise.groups:manage": {
		"Move user groups",
	},
	"workspacesAndBases:manage": {
		"Delete base",
		"Move workspaces",
		"Delete workspace",
		"Move base",
	},
}

var scopeToEndpointName = map[string]EndpointName{
	"schema.bases:read":        ListBasesEndpoint,
	"schema.bases:write":       UpdateBaseEndpoint,
	"webhook:manage":           ListWebhooksEndpoint,
	"block:manage":             ListBlockInstallationsEndpoint,
	"data.records:read":        ListRecordsEndpoint,
	"data.records:write":       CreateRecordEndpoint,
	"data.recordComments:read": ListRecordCommentsEndpoint,
}

var scopeToEndpoint map[string]Endpoint

func init() {
	scopeToEndpoint = make(map[string]Endpoint)
	for scope, endpointName := range scopeToEndpointName {
		if endpoint, exists := GetEndpoint(endpointName); exists {
			scopeToEndpoint[scope] = endpoint
		}
	}
}

func GetScopePermissions(scope string) ([]string, bool) {
	permission, exists := scopeToPermissions[scope]
	return permission, exists
}

func GetScopeEndpoint(scope string) (Endpoint, bool) {
	endpoint, exists := scopeToEndpoint[scope]
	return endpoint, exists
}
