package s3

import (
	tea "github.com/charmbracelet/bubbletea"

	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/components/textinputs"
)

func GetFields() tea.Model {
	bucket := textinputs.InputConfig{
		Label:       "S3 bucket name",
		Required:    true,
		Placeholder: "my-bucket-name",
	}

	return textinputs.New([]textinputs.InputConfig{bucket})
}
