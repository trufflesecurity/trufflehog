package github

import (
	tea "github.com/charmbracelet/bubbletea"

	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/components/textinputs"
)

func GetFields() tea.Model {
	org := textinputs.InputConfig{
		Label:       "Organization",
		Required:    true,
		Placeholder: "GitHub organization to scan.",
	}

	repo := textinputs.InputConfig{
		Label:       "Repository",
		Required:    true,
		Placeholder: "GitHub repo to scan.",
	}

	return textinputs.New([]textinputs.InputConfig{org, repo})
}
