package postman

import (
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/components/form"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/sources"
)

func init() { sources.Register(Definition()) }

// Definition returns the postman source configuration.
//
// The token is always emitted; the first non-empty of
// {workspace, collection, environment} is added too, matching the original
// behavior.
func Definition() sources.Definition {
	return sources.Definition{
		ID:          "postman",
		Title:       "Postman",
		Description: "Scan a collection, workspace, or environment from Postman, the API platform.",
		Tier:        sources.TierOSS,
		Note:        "Please enter an ID for a workspace, collection, or environment.",
		Command:     "postman",
		Fields: []form.FieldSpec{
			{
				Key:         "token",
				Label:       "Postman token",
				Help:        "Postman API key",
				Kind:        form.KindSecret,
				Placeholder: "PMAK-",
				Validators:  []form.Validate{form.Required()},
			},
			{
				Key:   "workspace",
				Label: "Workspace ID",
				Help:  "ID for workspace",
				Kind:  form.KindText,
			},
			{
				Key:   "collection",
				Label: "Collection ID",
				Help:  "ID for an API collection",
				Kind:  form.KindText,
			},
			{
				Key:   "environment",
				Label: "Environment ID",
				Help:  "ID for an environment",
				Kind:  form.KindText,
			},
		},
		BuildArgs: func(values map[string]string) []string {
			token := strings.TrimSpace(values["token"])
			var out []string
			if token != "" {
				out = append(out, "--token="+token)
			}
			for _, key := range []string{"workspace", "collection", "environment"} {
				if v := strings.TrimSpace(values[key]); v != "" {
					out = append(out, "--"+key+"="+v)
					break
				}
			}
			return out
		},
	}
}
