package github

import (
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/components/form"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/sources"
)

func init() { sources.Register(Definition()) }

// Definition returns the github source configuration.
func Definition() sources.Definition {
	fields := []form.FieldSpec{
		{
			Key:         "org",
			Label:       "Organization",
			Help:        "GitHub organization to scan.",
			Kind:        form.KindText,
			Placeholder: "trufflesecurity",
			Emit:        form.EmitLongFlagEq,
			Group:       "target",
		},
		{
			Key:         "repo",
			Label:       "Repository",
			Help:        "GitHub repo to scan.",
			Kind:        form.KindText,
			Placeholder: "https://github.com/trufflesecurity/test_keys",
			Emit:        form.EmitLongFlagEq,
			Group:       "target",
		},
	}

	return sources.Definition{
		ID:          "github",
		Title:       "GitHub",
		Description: "Scan GitHub repositories and/or organizations.",
		Tier:        sources.TierOSS,
		Note:        "Please enter an organization OR repository.",
		Command:     "github",
		Fields:      fields,
		Constraints: []form.Constraint{form.XOrGroup("target", 1, 1, fields)},
	}
}
