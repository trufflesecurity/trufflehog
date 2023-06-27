package git

import (
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/components/formfield"
)

func GetFields() []*formfield.FormField {
	gitUri := formfield.FormField{
		Label:       "Git URI",
		Required:    true,
		Placeholder: "",
		Help:        "",
		Component:   nil,
	}

	return []*formfield.FormField{
		&gitUri,
	}
}
