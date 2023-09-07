package trello

import (
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/components/textinputs"
)

type trelloCmdModel struct {
	textinputs.Model
}

func GetFields() trelloCmdModel {
	apiKey := textinputs.InputConfig{
		Label:       "API Key",
		Key:         "api_key",
		Required:    true,
		Placeholder: "Your Trello API key",
	}

	token := textinputs.InputConfig{
		Label:       "Token",
		Key:         "token",
		Required:    true,
		Placeholder: "Your Trello token",
	}

	boardIds := textinputs.InputConfig{
		Label:       "Board IDs",
		Key:         "board_ids",
		Required:    true,
		Placeholder: "Comma-separated list of Trello board ID(s)",
	}

	return trelloCmdModel{textinputs.New([]textinputs.InputConfig{apiKey, token, boardIds})}
}

func (m trelloCmdModel) Cmd() string {
	var command []string
	command = append(command, "trufflehog", "trello")

	inputs := m.GetInputs()

	if inputs["api_key"] != "" {
		command = append(command, "--api-key="+inputs["api_key"])
	}
	if inputs["token"] != "" {
		command = append(command, "--token="+inputs["token"])
	}
	if inputs["board_ids"] != "" {
		command = append(command, "--board-ids="+inputs["board_ids"])
	}

	return strings.Join(command, " ")
}

func (m trelloCmdModel) Summary() string {
	inputs := m.GetInputs()
	labels := m.GetLabels()
	keys := []string{"api_key", "token", "board_ids"}

	return common.SummarizeSource(keys, inputs, labels)
}
