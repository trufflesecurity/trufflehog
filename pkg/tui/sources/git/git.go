package git

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/components/textinputs"
)

func GetFields() tea.Model {
	uri := textinputs.InputConfig{
		Label:       "Git URI",
		Required:    true,
		Placeholder: "git@github.com:trufflesecurity/trufflehog.git.",
	}

	return textinputs.New([]textinputs.InputConfig{uri})
}
