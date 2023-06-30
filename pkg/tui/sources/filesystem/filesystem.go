package filesystem

import (
	tea "github.com/charmbracelet/bubbletea"

	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/components/textinputs"
)

func GetFields() tea.Model {
	path := textinputs.InputConfig{
		Label:       "Path",
		Required:    true,
		Help:        "Files and directories to scan. Separate by space if multiple.",
		Placeholder: "path/to/file.txt path/to/another/dir",
	}

	return textinputs.New([]textinputs.InputConfig{path})
}
