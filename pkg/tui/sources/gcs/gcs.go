package gcs

import (
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/components/textinputs"
)

type gcsCmdModel struct {
	textinputs.Model
}

func GetFields() gcsCmdModel {
	projectId := textinputs.InputConfig{
		Label:       "Project ID",
		Key:         "project_id",
		Required:    true,
		Placeholder: "my-project",
	}

	return gcsCmdModel{textinputs.New([]textinputs.InputConfig{projectId})}
}

func (m gcsCmdModel) Cmd() string {
	var command []string
	command = append(command, "trufflehog", "gcs")

	inputs := m.GetInputs()
	if inputs["project_id"] != "" {
		command = append(command, "--project_id="+inputs["project_id"])
	}

	command = append(command, "--cloud-environment")
	return strings.Join(command, " ")
}

func (m gcsCmdModel) Summary() string {
	inputs := m.GetInputs()
	labels := m.GetLabels()

	keys := []string{"project_id"}
	return common.SummarizeSource(keys, inputs, labels)
}
