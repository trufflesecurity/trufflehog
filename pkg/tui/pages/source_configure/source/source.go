package source

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/pages/source_configure/source/git"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/pages/source_configure/source/github"
)

type SourceForm struct {
	sourceType string
	fields     tea.Model
}

func NewSourceForm(sourceType string) *SourceForm {
	var sourceFields tea.Model
	switch sourceType {
	case "git":
		sourceFields = git.GetFields()
	case "github":
		sourceFields = github.GetFields()
	default:
		sourceFields = nil
	}

	return &SourceForm{
		sourceType: sourceType,
		fields:     sourceFields,
	}
}

func (s *SourceForm) GetFields() tea.Model {
	return s.fields
}
