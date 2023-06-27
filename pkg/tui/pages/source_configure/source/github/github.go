package github

import (
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/components/formfield"
)

func GetFields() []*formfield.FormField {
	repo := formfield.FormField{
		Label:       "Repository",
		Help:        "GitHub repo to scan.",
		Required:    false,
		Placeholder: "https://github.com/trufflesecurity/test_keys",
		Component:   nil,
	}

	org := formfield.FormField{
		Label:       "Organization",
		Help:        "GitHub organization to scan.",
		Required:    false,
		Placeholder: "trufflesecurity",
		Component:   nil,
	}

	return []*formfield.FormField{
		&repo,
		&org,
	}
}
