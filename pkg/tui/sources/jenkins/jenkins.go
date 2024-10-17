package jenkins

import (
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/components/textinputs"
)

type jenkinsCmdModel struct {
	textinputs.Model
}

func GetNote() string {
	return "If no username and password are provided, TruffleHog will attempt an unauthenticated Jenkins scan."
}

func GetFields() jenkinsCmdModel {
	return jenkinsCmdModel{textinputs.New([]textinputs.InputConfig{
		{
			Label:       "Endpoint URL",
			Key:         "url",
			Required:    true,
			Help:        "URL of the Jenkins server.",
			Placeholder: "https://jenkins.example.com",
		},
		{
			Label:    "Username",
			Key:      "username",
			Required: false,
			Help:     "For authenticated scans - pairs with password.",
		},
		{
			Label:    "Password",
			Key:      "password",
			Required: false,
			Help:     "For authenticated scans - pairs with username.",
		}})}
}

func checkIsAuthenticated(inputs map[string]textinputs.Input) bool {
	username := inputs["username"].Value
	password := inputs["password"].Value

	return username != "" && password != ""
}

func (m jenkinsCmdModel) Cmd() string {
	var command []string
	command = append(command, "trufflehog", "jenkins")
	inputs := m.GetInputs()

	keys := []string{"url"}
	if checkIsAuthenticated(inputs) {
		keys = append(keys, "username", "password")
	}

	for _, key := range keys {
		val, ok := inputs[key]
		if !ok || val.Value == "" {
			continue
		}
		command = append(command, "--"+key+"="+val.Value)
	}

	return strings.Join(command, " ")
}

func (m jenkinsCmdModel) Summary() string {
	inputs := m.GetInputs()
	labels := m.GetLabels()

	summaryKeys := []string{"url"}
	if checkIsAuthenticated(inputs) {
		summaryKeys = append(summaryKeys, "username", "password")
	}

	return common.SummarizeSource(summaryKeys, inputs, labels)
}
