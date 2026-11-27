package jenkins

import (
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/components/form"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/sources"
)

func init() { sources.Register(Definition()) }

// Definition returns the jenkins source configuration.
//
// Username + password are emitted only when both are set; either alone is
// dropped so we don't accidentally half-authenticate against a server that
// would then fall back to anonymous auth silently.
func Definition() sources.Definition {
	return sources.Definition{
		ID:          "jenkins",
		Title:       "Jenkins",
		Description: "Scan Jenkins, a CI/CD platform. (Recently open-sourced from enterprise!)",
		Tier:        sources.TierOSS,
		Note:        "If no username and password are provided, TruffleHog will attempt an unauthenticated Jenkins scan.",
		Command:     "jenkins",
		Fields: []form.FieldSpec{
			{
				Key:         "url",
				Label:       "Endpoint URL",
				Help:        "URL of the Jenkins server.",
				Kind:        form.KindText,
				Placeholder: "https://jenkins.example.com",
				Validators:  []form.Validate{form.Required()},
			},
			{
				Key:   "username",
				Label: "Username",
				Help:  "For authenticated scans - pairs with password.",
				Kind:  form.KindText,
			},
			{
				Key:   "password",
				Label: "Password",
				Help:  "For authenticated scans - pairs with username.",
				Kind:  form.KindSecret,
			},
		},
		BuildArgs: func(values map[string]string) []string {
			url := strings.TrimSpace(values["url"])
			username := strings.TrimSpace(values["username"])
			password := strings.TrimSpace(values["password"])

			var out []string
			if url != "" {
				out = append(out, "--url="+url)
			}
			if username != "" && password != "" {
				out = append(out, "--username="+username, "--password="+password)
			}
			return out
		},
	}
}
