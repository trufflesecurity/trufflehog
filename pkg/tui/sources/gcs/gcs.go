package gcs

import (
	tea "github.com/charmbracelet/bubbletea"

	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/components/textinputs"
)

func GetFields() tea.Model {
	projectId := textinputs.InputConfig{
		Label:       "Project ID",
		Required:    true,
		Placeholder: "my-project",
	}

	return textinputs.New([]textinputs.InputConfig{projectId})
}
