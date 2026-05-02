package elasticsearch

import (
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/components/form"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/sources"
)

// connectionKeysFor returns the subset of keys that should be emitted based
// on which field the user filled in first. The original textinputs-based
// implementation locked the connection mode on the first non-empty value and
// only emitted keys that belong to that mode, which is what we replicate
// here.
func connectionKeysFor(values map[string]string) []string {
	keys := []string{"username", "password", "serviceToken", "cloudId", "apiKey"}
	for _, k := range keys {
		if strings.TrimSpace(values[k]) == "" {
			continue
		}
		switch k {
		case "username", "password":
			return []string{"username", "password", "nodes"}
		case "serviceToken":
			return []string{"serviceToken", "nodes"}
		case "cloudId", "apiKey":
			return []string{"cloudId", "apiKey"}
		}
	}
	return nil
}

func init() { sources.Register(Definition()) }

// Definition returns the elasticsearch source configuration.
func Definition() sources.Definition {
	return sources.Definition{
		ID:          "elasticsearch",
		Title:       "Elasticsearch",
		Description: "Scan your Elasticsearch cluster or Elastic Cloud instance.",
		Tier:        sources.TierOSS,
		Note:        "To connect to a local cluster, please provide the node IPs and either (username AND password) OR service token. ⭐\n⭐ To connect to a cloud cluster, please provide cloud ID AND API key.",
		Command:     "elasticsearch",
		Fields: []form.FieldSpec{
			{
				Key:   "nodes",
				Label: "Elastic node(s)",
				Help:  "Elastic node IPs - for scanning local clusters. Separate by space if multiple.",
				Kind:  form.KindText,
			},
			{
				Key:   "username",
				Label: "Username",
				Help:  "Elasticsearch username. Pairs with password. For scanning local clusters.",
				Kind:  form.KindText,
			},
			{
				Key:   "password",
				Label: "Password",
				Help:  "Elasticsearch password. Pairs with username. For scanning local clusters.",
				Kind:  form.KindSecret,
			},
			{
				Key:   "serviceToken",
				Label: "Service Token",
				Help:  "Elastic service token. For scanning local clusters.",
				Kind:  form.KindSecret,
			},
			{
				Key:   "cloudId",
				Label: "Cloud ID",
				Help:  "Elastic cloud ID. Pairs with API key. For scanning cloud clusters.",
				Kind:  form.KindText,
			},
			{
				Key:   "apiKey",
				Label: "API Key",
				Help:  "Elastic API key. Pairs with cloud ID. For scanning cloud clusters.",
				Kind:  form.KindSecret,
			},
		},
		BuildArgs: func(values map[string]string) []string {
			var out []string
			for _, key := range connectionKeysFor(values) {
				val := strings.TrimSpace(values[key])
				if val == "" {
					continue
				}
				if key == "nodes" {
					for _, node := range strings.Fields(val) {
						out = append(out, "--nodes="+node)
					}
					continue
				}
				out = append(out, "--"+key+"="+val)
			}
			return out
		},
	}
}
