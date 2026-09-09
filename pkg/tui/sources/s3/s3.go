package s3

import (
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/components/form"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/sources"
)

func init() { sources.Register(Definition()) }

// Definition returns the s3 source configuration.
//
// Multiple bucket names entered as whitespace-separated values each emit a
// distinct --bucket=<name> token.
func Definition() sources.Definition {
	return sources.Definition{
		ID:          "s3",
		Title:       "AWS S3",
		Description: "Scan Amazon S3 buckets.",
		Tier:        sources.TierOSS,
		Command:     "s3",
		Fields: []form.FieldSpec{
			{
				Key:         "bucket",
				Label:       "S3 bucket name(s)",
				Help:        "Buckets to scan. Separate by space if multiple.",
				Kind:        form.KindText,
				Placeholder: "truffletestbucket",
				Emit:        form.EmitRepeatedLongFlagEq,
				Validators:  []form.Validate{form.Required()},
			},
		},
	}
}
