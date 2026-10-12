package circleci

import (
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/components/form"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/sources"
)

func init() { sources.Register(Definition()) }

// Definition returns the circleci source configuration.
func Definition() sources.Definition {
	return sources.Definition{
		ID:          "circleci",
		Title:       "CircleCI",
		Description: "Scan CircleCI, a CI/CD platform.",
		Tier:        sources.TierOSS,
		Command:     "circleci",
		Fields: []form.FieldSpec{
			{
				Key:         "token",
				Label:       "API Token",
				Kind:        form.KindSecret,
				Placeholder: "top secret token",
				Emit:        form.EmitLongFlagEq,
				Validators:  []form.Validate{form.Required()},
			},
		},
	}
}
