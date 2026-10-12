package docker

import (
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/components/form"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/sources"
)

func init() { sources.Register(Definition()) }

// Definition returns the docker source configuration.
//
// The user enters one or more image references separated by whitespace; the
// form emits one --image=<value> per image, matching the original behavior.
func Definition() sources.Definition {
	return sources.Definition{
		ID:          "docker",
		Title:       "Docker",
		Description: "Scan a Docker instance, a containerized application.",
		Tier:        sources.TierOSS,
		Command:     "docker",
		Fields: []form.FieldSpec{
			{
				Key:         "image",
				Label:       "Docker image(s)",
				Help:        "Separate by space if multiple.",
				Kind:        form.KindText,
				Placeholder: "trufflesecurity/secrets",
				Emit:        form.EmitRepeatedLongFlagEq,
				Validators:  []form.Validate{form.Required()},
			},
		},
	}
}
