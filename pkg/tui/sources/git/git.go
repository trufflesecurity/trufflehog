package git

import (
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/components/form"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/sources"
)

func init() { sources.Register(Definition()) }

// Definition returns the git source configuration.
func Definition() sources.Definition {
	return sources.Definition{
		ID:          "git",
		Title:       "Git",
		Description: "Scan git repositories.",
		Tier:        sources.TierOSS,
		Command:     "git",
		Fields: []form.FieldSpec{
			{
				Key:         "uri",
				Label:       "Git URI",
				Help:        "file:// for local git repos",
				Kind:        form.KindText,
				Placeholder: "git@github.com:trufflesecurity/trufflehog.git",
				Emit:        form.EmitPositional,
				Validators:  []form.Validate{form.Required()},
			},
		},
	}
}
