package docker

import (
	tea "github.com/charmbracelet/bubbletea"

	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/components/textinputs"
)

func GetFields() tea.Model {
	images := textinputs.InputConfig{
		Label:       "Docker image(s)",
		Required:    true,
		Help:        "Separate by space if multiple.",
		Placeholder: "trufflesecurity/secrets",
	}

	return textinputs.New([]textinputs.InputConfig{images})
}
