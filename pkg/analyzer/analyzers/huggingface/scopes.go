package huggingface

//nolint:unused
var repo_scopes = map[string]string{
	"repo.content.read": "Read access to contents",
	"discussion.write":  "Interact with discussions / Open pull requests",
	"repo.write":        "Write access to contents/settings",
}

var org_scopes_order = []string{
	"Repos",
	"Collections",
	"Inference endpoints",
	"Org settings",
}

var org_scopes = map[string]map[string]string{
	"Repos": {
		"repo.content.read": "Read access to contents of all repos",
		"discussion.write":  "Interact with discussions / Open pull requests on all repos",
		"repo.write":        "Write access to contents/settings of all repos",
	},
	"Collections": {
		"collection.read":  "Read access to all collections",
		"collection.write": "Write access to all collections",
	},
	"Inference endpoints": {
		"inference.endpoints.infer.write": "Make calls to inference endpoints",
		"inference.endpoints.write":       "Manage inference endpoints",
	},
	"Org settings": {
		"org.read":  "Read access to organization's settings",
		"org.write": "Write access to organization's settings / member management",
	},
}

var user_scopes_order = []string{
	"Billing",
	"Collections",
	"Discussions & Posts",
	"Inference",
	"Repos",
	"Webhooks",
}

var user_scopes = map[string]map[string]string{
	"Billing": {
		"user.billing.read": "Read access to user's billing usage",
	},
	"Collections": {
		"collection.read":  "Read access to all ollections under user's namespace",
		"collection.write": "Write access to all collections under user's namespace",
	},
	"Discussions & Posts": {
		// Note: prepending global. to scopes that are nested under "global" in fine-grained permissions JSON
		// otherwise they would overlap with user scopes under the "scoped" JSON
		"discussion.write":        "Interact with discussions / Open pull requests on repos under user's namespace",
		"global.discussion.write": "Interact with discussions / Open pull requests on external repos",
		"global.post.write":       "Interact with posts",
	},
	"Inference": {
		"global.inference.serverless.write": "Make calls to the serverless Inference API",
		"inference.endpoints.infer.write":   "Make calls to inference endpoints",
		"inference.endpoints.write":         "Manage inference endpoints",
	},
	"Repos": {
		"repo.content.read": "Read access to contents of all repos under user's namespace",
		"repo.write":        "Write access to contents/settings of all repos under user's namespace",
	},
	"Webhooks": {
		"user.webhooks.read":  "Access webhooks data",
		"user.webhooks.write": "Create and manage webhooks",
	},
}
