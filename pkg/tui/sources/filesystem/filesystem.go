package filesystem

import (
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/components/form"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/sources"
)

func init() { sources.Register(Definition()) }

// Definition returns the filesystem source configuration.
func Definition() sources.Definition {
	return sources.Definition{
		ID:          "filesystem",
		Title:       "Filesystem",
		Description: "Scan your filesystem by selecting what directories to scan.",
		Tier:        sources.TierOSS,
		Command:     "filesystem",
		Fields: []form.FieldSpec{
			{
				Key:         "path",
				Label:       "Path",
				Help:        "Files and directories to scan. Separate by space if multiple.",
				Kind:        form.KindText,
				Placeholder: "path/to/file.txt path/to/another/dir",
				Emit:        form.EmitPositional,
				Validators:  []form.Validate{form.Required()},
			},
		},
	}
}
