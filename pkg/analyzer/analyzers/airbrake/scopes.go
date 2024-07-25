package airbrake

var scope_order = [][]string{
	{"Authentication"},
	{"Performance Monitoring"},
	{"Error Notification"},
	{"Projects"},
	{"Deploys"},
	{"Groups"},
	{"Notices"},
	{"Project Activities"},
	{"Source Maps"},
	{"iOS Crash Reports"},
}

var scope_mapping = map[string][]string{
	"Authentication":         {"Create user token"},
	"Performance Monitoring": {"Route performance endpoint", "Routes breakdown endpoint", "Database query stats", "Queue stats"},
	"Error Notification":     {"Create notice"},
	"Projects":               {"List projects", "Show projects"},
	"Deploys":                {"Create deploy", "List deploys", "Show deploy"},
	"Groups":                 {"List groups", "Show group", "Mute group", "Unmute group", "Delete group", "List groups across all projects", "Show group statistics"},
	"Notices":                {"List notices", "Show notice status"},
	"Project Activities":     {"List project activities", "Show project statistics"},
	"Source Maps":            {"Create source map", "List source maps", "Show source map", "Delete source map"},
	"iOS Crash Reports":      {"Create iOS crash report"},
}
