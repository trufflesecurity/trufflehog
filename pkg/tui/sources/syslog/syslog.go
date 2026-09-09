package syslog

import (
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/components/form"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/sources"
)

func init() { sources.Register(Definition()) }

// Definition returns the syslog source configuration.
func Definition() sources.Definition {
	return sources.Definition{
		ID:          "syslog",
		Title:       "Syslog",
		Description: "Scan syslog, event data logs.",
		Tier:        sources.TierOSS,
		Command:     "syslog",
		Fields: []form.FieldSpec{
			{
				Key:         "address",
				Label:       "Address",
				Help:        "Address and port to listen on for syslog",
				Kind:        form.KindText,
				Placeholder: "127.0.0.1:514",
				Emit:        form.EmitLongFlagEq,
				Validators:  []form.Validate{form.Required()},
			},
			{
				Key:         "protocol",
				Label:       "Protocol",
				Help:        "udp or tcp",
				Kind:        form.KindSelect,
				Emit:        form.EmitLongFlagEq,
				Default:     "tcp",
				Options: []form.SelectOption{
					{Label: "TCP", Value: "tcp"},
					{Label: "UDP", Value: "udp"},
				},
				Validators: []form.Validate{form.Required(), form.OneOf("tcp", "udp")},
			},
			{
				Key:         "cert",
				Label:       "TLS Certificate",
				Help:        "Path to TLS certificate",
				Kind:        form.KindText,
				Placeholder: "/path/to/cert",
				Emit:        form.EmitLongFlagEq,
				Validators:  []form.Validate{form.Required()},
			},
			{
				Key:         "key",
				Label:       "TLS Key",
				Help:        "Path to TLS key",
				Kind:        form.KindText,
				Placeholder: "/path/to/key",
				Emit:        form.EmitLongFlagEq,
				Validators:  []form.Validate{form.Required()},
			},
			{
				Key:         "format",
				Label:       "Log format",
				Help:        "Can be rfc3164 or rfc5424",
				Kind:        form.KindSelect,
				Emit:        form.EmitLongFlagEq,
				Default:     "rfc3164",
				Options: []form.SelectOption{
					{Label: "rfc3164", Value: "rfc3164"},
					{Label: "rfc5424", Value: "rfc5424"},
				},
				Validators: []form.Validate{form.Required(), form.OneOf("rfc3164", "rfc5424")},
			},
		},
	}
}
