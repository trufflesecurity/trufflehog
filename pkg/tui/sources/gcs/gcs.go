package gcs

import (
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/components/form"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/sources"
)

func init() { sources.Register(Definition()) }

// Definition returns the gcs source configuration.
func Definition() sources.Definition {
	return sources.Definition{
		ID:          "gcs",
		Title:       "GCS (Google Cloud Storage)",
		Description: "Scan a Google Cloud Storage instance.",
		Tier:        sources.TierOSS,
		Command:     "gcs",
		Fields: []form.FieldSpec{
			{
				Key:         "project-id",
				Label:       "Project ID",
				Kind:        form.KindText,
				Placeholder: "trufflehog-testing",
				Emit:        form.EmitLongFlagEq,
				Validators:  []form.Validate{form.Required()},
			},
		},
		// Always scan the default cloud environment; matches prior behavior.
		ExtraArgs: []string{"--cloud-environment"},
	}
}
