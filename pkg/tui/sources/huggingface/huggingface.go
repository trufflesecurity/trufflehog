package huggingface

import (
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/components/form"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/sources"
)

func init() { sources.Register(Definition()) }

// Definition returns the huggingface source configuration.
//
// All non-empty fields are emitted; the user may fill multiple of
// {org, user, model, space, dataset}.
func Definition() sources.Definition {
	return sources.Definition{
		ID:          "huggingface",
		Title:       "Hugging Face",
		Description: "Scan Hugging Face, an AI/ML community.",
		Tier:        sources.TierOSS,
		Note:        "Please enter the organization, user, model, space, or dataset you would like to scan.",
		Command:     "huggingface",
		Fields: []form.FieldSpec{
			{
				Key:   "org",
				Label: "Organization",
				Help:  "Hugging Face organization name. This will scan all models, datasets, and spaces belonging to the organization.",
				Kind:  form.KindText,
				Emit:  form.EmitLongFlagEq,
				Group: "target",
			},
			{
				Key:   "user",
				Label: "Username",
				Help:  "Hugging Face user. This will scan all models, datasets, and spaces belonging to the user.",
				Kind:  form.KindText,
				Emit:  form.EmitLongFlagEq,
				Group: "target",
			},
			{
				Key:   "model",
				Label: "Model",
				Help:  "Hugging Face model. Example: org/model_name or user/model_name",
				Kind:  form.KindText,
				Emit:  form.EmitLongFlagEq,
				Group: "target",
			},
			{
				Key:   "space",
				Label: "Space",
				Help:  "Hugging Face space. Example: org/space_name or user/space_name.",
				Kind:  form.KindText,
				Emit:  form.EmitLongFlagEq,
				Group: "target",
			},
			{
				Key:   "dataset",
				Label: "Dataset",
				Help:  "Hugging Face dataset. Example: org/dataset_name or user/dataset_name.",
				Kind:  form.KindText,
				Emit:  form.EmitLongFlagEq,
				Group: "target",
			},
		},
	}
}
