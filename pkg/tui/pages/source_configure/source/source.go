package source

import (
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/components/formfield"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/pages/source_configure/source/git"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/pages/source_configure/source/github"
)

type SourceForm struct {
	sourceType string
	fields     []*formfield.FormField
}

func NewSourceForm(sourceType string) *SourceForm {
	var sourceFields []*formfield.FormField
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

func (s *SourceForm) GetFields() []*formfield.FormField {
	return s.fields
}
