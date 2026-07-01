package gitlab

import (
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/components/form"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/sources"
)

func init() { sources.Register(Definition()) }

// Definition returns the gitlab source configuration.
func Definition() sources.Definition {
	return sources.Definition{
		ID:          "gitlab",
		Title:       "GitLab",
		Description: "Scan GitLab repositories.",
		Tier:        sources.TierOSS,
		Command:     "gitlab",
		Fields: []form.FieldSpec{
			{
				Key:         "token",
				Label:       "GitLab token",
				Help:        "Personal access token with read access",
				Kind:        form.KindSecret,
				Placeholder: "glpat-",
				Emit:        form.EmitLongFlagEq,
				Validators:  []form.Validate{form.Required()},
			},
		},
	}
}
