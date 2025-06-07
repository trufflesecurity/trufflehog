package git

import (
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/components/textinputs"
)

type gitCmdModel struct {
	textinputs.Model
}

func GetFields() gitCmdModel {
	uri := textinputs.InputConfig{
		Label:       "Git URI",
		Key:         "uri",
		Help:        "file:// for local git repos",
		Required:    true,
		Placeholder: "git@github.com:trufflesecurity/trufflehog.git",
	}

	return gitCmdModel{textinputs.New([]textinputs.InputConfig{uri})}
}

func (m gitCmdModel) Cmd() string {
	var command []string
	command = append(command, "trufflehog", "git")

	inputs := m.GetInputs()

	command = append(command, inputs["uri"].Value)

	return strings.Join(command, " ")
}

func (m gitCmdModel) Summary() string {
	inputs := m.GetInputs()
	labels := m.GetLabels()

	keys := []string{"uri"}
	return common.SummarizeSource(keys, inputs, labels)
}
