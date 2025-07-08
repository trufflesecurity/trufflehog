package postman

import (
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/components/textinputs"
)

type postmanCmdModel struct {
	textinputs.Model
}

func GetNote() string {
	return "Please enter an ID for a workspace, collection, or environment."
}

func GetFields() postmanCmdModel {
	token := textinputs.InputConfig{
		Label:       "Postman token",
		Key:         "token",
		Required:    true,
		Help:        "Postman API key",
		Placeholder: "PMAK-",
	}
	workspace := textinputs.InputConfig{
		Label:    "Workspace ID",
		Key:      "workspace",
		Required: false,
		Help:     "ID for workspace",
	}
	collection := textinputs.InputConfig{
		Label:    "Collection ID",
		Key:      "collection",
		Required: false,
		Help:     "ID for an API collection",
	}
	environment := textinputs.InputConfig{
		Label:    "Environment ID",
		Key:      "environment",
		Required: false,
		Help:     "ID for an environment",
	}

	return postmanCmdModel{textinputs.New([]textinputs.InputConfig{token, workspace, collection, environment})}
}

func findFirstNonEmptyKey(inputs map[string]textinputs.Input, keys []string) string {
	for _, key := range keys {
		if val, ok := inputs[key]; ok && val.Value != "" {
			return key
		}
	}
	return ""
}

func (m postmanCmdModel) Cmd() string {
	var command []string
	command = append(command, "trufflehog", "postman")

	inputs := m.GetInputs()
	keys := []string{"workspace", "collection", "environment"}

	command = append(command, "--token="+inputs["token"].Value)
	key := findFirstNonEmptyKey(inputs, keys)
	if key != "" {
		command = append(command, "--"+key+"="+inputs[key].Value)
	}
	return strings.Join(command, " ")
}

func (m postmanCmdModel) Summary() string {
	inputs := m.GetInputs()
	labels := m.GetLabels()
	keys := []string{"token", "workspace", "collection", "environment"}

	summaryKeys := []string{"token"}
	key := findFirstNonEmptyKey(inputs, keys[1:])
	if key != "" {
		summaryKeys = append(summaryKeys, key)
	}
	return common.SummarizeSource(summaryKeys, inputs, labels)
}
