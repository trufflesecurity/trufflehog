package formfield

import (
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/styles"
)

type FormField struct {
	Label       string
	Required    bool
	Help        string
	Placeholder string
	Component   common.Component
}

func NewFormField(common common.Common) *FormField {
	return &FormField{}
}

func (field *FormField) ViewLabel() string {
	var label strings.Builder
	if field.Required {
		label.WriteString(styles.BoldTextStyle.Render(field.Label) + "*\n")
	} else {
		label.WriteString(styles.BoldTextStyle.Render(field.Label) + "\n")
	}

	return label.String()
}

func (field *FormField) ViewHelp() string {
	var help strings.Builder
	help.WriteString(styles.HintTextStyle.Render(field.Help) + "\n")

	return help.String()
}
