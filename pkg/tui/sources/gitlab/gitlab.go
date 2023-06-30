package gitlab

import (
	tea "github.com/charmbracelet/bubbletea"

	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/components/textinputs"
)

func GetFields() tea.Model {
	token := textinputs.InputConfig{
		Label:       "GitLab token",
		Required:    true,
		Help:        "Personal access token with read access",
		Placeholder: "glpat-",
	}

	return textinputs.New([]textinputs.InputConfig{token})
}
