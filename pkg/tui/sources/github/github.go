package github

import (
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/components/textinputs"
)

type githubCmdModel struct {
	textinputs.Model
}

func GetNote() string {
	return "Please enter an organization OR repository."
}

func GetFields() githubCmdModel {
	org := textinputs.InputConfig{
		Label:       "Organization",
		Key:         "org",
		Required:    false,
		Help:        "GitHub organization to scan.",
		Placeholder: "https://github.com/trufflesecurity",
	}

	repo := textinputs.InputConfig{
		Label:       "Repository",
		Key:         "repo",
		Required:    false,
		Help:        "GitHub repo to scan.",
		Placeholder: "https://github.com/trufflesecurity/test_keys",
	}

	return githubCmdModel{textinputs.New([]textinputs.InputConfig{org, repo})}
}

func (m githubCmdModel) Cmd() string {
	var command []string
	command = append(command, "trufflehog", "github")

	inputs := m.GetInputs()

	if inputs["org"] != "" {
		command = append(command, "--org="+inputs["org"])
	}

	if inputs["repo"] != "" {
		command = append(command, "--repo="+inputs["repo"])
	}

	return strings.Join(command, " ")
}

func (m githubCmdModel) Summary() string {
	inputs := m.GetInputs()
	labels := m.GetLabels()

	keys := []string{"org", "repo"}
	return common.SummarizeSource(keys, inputs, labels)
}
