package huggingface

import (
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/components/textinputs"
)

type huggingFaceCmdModel struct {
	textinputs.Model
}

func GetNote() string {
	return "Please enter the organization, user, model, space, or dataset you would like to scan."
}

func GetFields() huggingFaceCmdModel {
	org := textinputs.InputConfig{
		Label:    "Organization",
		Key:      "org",
		Required: false,
		Help:     "Hugging Face organization name. This will scan all models, datasets, and spaces belonging to the organization.",
	}
	user := textinputs.InputConfig{
		Label:    "Username",
		Key:      "user",
		Required: false,
		Help:     "Hugging Face user. This will scan all models, datasets, and spaces belonging to the user.",
	}
	model := textinputs.InputConfig{
		Label:    "Model",
		Key:      "model",
		Required: false,
		Help:     "Hugging Face model. Example: org/model_name or user/model_name",
	}
	space := textinputs.InputConfig{
		Label:    "Space",
		Key:      "space",
		Required: false,
		Help:     "Hugging Face space. Example: org/space_name or user/space_name.",
	}
	dataset := textinputs.InputConfig{
		Label:    "Dataset",
		Key:      "dataset",
		Required: false,
		Help:     "Hugging Face dataset. Example: org/dataset_name or user/dataset_name.",
	}

	return huggingFaceCmdModel{textinputs.New([]textinputs.InputConfig{org, user, model, space, dataset})}
}

func (m huggingFaceCmdModel) Cmd() string {
	var command []string
	command = append(command, "trufflehog", "huggingface")

	inputs := m.GetInputs()
	keys := []string{"org", "user", "model", "space", "dataset"}

	for _, key := range keys {
		val, ok := inputs[key]
		if !ok || val.Value == "" {
			continue
		}

		command = append(command, "--"+key+"="+val.Value)
	}

	return strings.Join(command, " ")
}

func (m huggingFaceCmdModel) Summary() string {
	inputs := m.GetInputs()
	labels := m.GetLabels()
	keys := []string{"org", "user", "model", "space", "dataset"}
	return common.SummarizeSource(keys, inputs, labels)
}
