package gitlab

var gitlab_scopes = map[string]string{
	"api":               "Grants complete read/write access to the API, including all groups and projects, the container registry, the dependency proxy, and the package registry. Also grants complete read/write access to the registry and repository using Git over HTTP.",
	"read_user":         "Grants read-only access to the authenticated user’s profile through the /user API endpoint, which includes username, public email, and full name. Also grants access to read-only API endpoints under /users.",
	"read_api":          "Grants read access to the API, including all groups and projects, the container registry, and the package registry.",
	"read_repository":   "Grants read-only access to repositories on private projects using Git-over-HTTP or the Repository Files API.",
	"write_repository":  "Grants read-write access to repositories on private projects using Git-over-HTTP (not using the API).",
	"read_registry":     "Grants read-only (pull) access to container registry images if a project is private and authorization is required. Available only when the container registry is enabled.",
	"write_registry":    "Grants read-write (push) access to container registry images if a project is private and authorization is required. Available only when the container registry is enabled.",
	"sudo":              "Grants permission to perform API actions as any user in the system, when authenticated as an administrator.",
	"admin_mode":        "Grants permission to perform API actions as an administrator, when Admin Mode is enabled. (Introduced in GitLab 15.8.)",
	"create_runner":     "Grants permission to create runners.",
	"manage_runner":     "Grants permission to manage runners.",
	"ai_features":       "Grants permission to perform API actions for GitLab Duo. This scope is designed to work with the GitLab Duo Plugin for JetBrains. For all other extensions, see scope requirements.",
	"k8s_proxy":         "Grants permission to perform Kubernetes API calls using the agent for Kubernetes.",
	"read_service_ping": "Grant access to download Service Ping payload through the API when authenticated as an admin use. (Introduced in GitLab 16.8.",
}

var access_level_map = map[int]string{
	0:  "No access",
	5:  "Minimal access",
	10: "Guest",
	20: "Reporter",
	30: "Developer",
	40: "Maintainer",
	50: "Owner",
}
