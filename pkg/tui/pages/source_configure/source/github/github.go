package github

import (
	tea "github.com/charmbracelet/bubbletea"

	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/components/textinputs"
)

func GetFields() tea.Model {
	org := textinputs.InputConfig{
		Label:       "Organization",
		Required:    true,
		Help:        "GitHub organization to scan.",
		Placeholder: "https://github.com/trufflesecurity",
	}

	repo := textinputs.InputConfig{
		Label:       "Repository",
		Required:    true,
		Help:        "GitHub repo to scan.",
		Placeholder: "https://github.com/trufflesecurity/test_keys",
	}

	return textinputs.New([]textinputs.InputConfig{org, repo})
}
