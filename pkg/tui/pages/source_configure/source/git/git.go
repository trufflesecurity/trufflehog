package git

import (
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/components/formfield"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/components/textinput"
)

func GetFields() []*formfield.FormField {
	gitUri := formfield.FormField{
		Label:     "Git URI",
		Required:  true,
		Help:      "",
		Component: textinput.New(""),
	}

	return []*formfield.FormField{
		&gitUri,
	}
}
