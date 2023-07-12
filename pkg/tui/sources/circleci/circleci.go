package circleci

import (
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/components/textinputs"
)

type circleCiCmdModel struct {
	textinputs.Model
}

func GetFields() circleCiCmdModel {
	token := textinputs.InputConfig{
		Label:       "API Token",
		Key:         "token",
		Required:    true,
		Placeholder: "top secret token",
	}

	return circleCiCmdModel{textinputs.New([]textinputs.InputConfig{token})}
}

func (m circleCiCmdModel) Cmd() string {
	var command []string
	command = append(command, "trufflehog", "circleci")

	inputs := m.GetInputs()

	if inputs["token"] != "" {
		command = append(command, "--token="+inputs["token"])
	}

	return strings.Join(command, " ")
}
