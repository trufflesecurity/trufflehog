package circleci

import (
	tea "github.com/charmbracelet/bubbletea"

	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/components/textinputs"
)

// TODO: review fields

func GetFields() tea.Model {
	token := textinputs.InputConfig{
		Label:       "API Token",
		Required:    true,
		Placeholder: "top secret token",
	}

	return textinputs.New([]textinputs.InputConfig{token})
}
