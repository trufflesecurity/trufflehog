package syslog

import (
	tea "github.com/charmbracelet/bubbletea"

	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/components/textinputs"
)

// TODO: review fields
func GetFields() tea.Model {
	protocol := textinputs.InputConfig{
		Label:       "Protocol",
		Required:    true,
		Help:        "udp or tcp",
		Placeholder: "tcp",
	}

	listenAddress := textinputs.InputConfig{
		Label:       "Address",
		Help:        "Address and port to listen on for syslog",
		Required:    true,
		Placeholder: "127.0.0.1:514",
	}

	tlsCert := textinputs.InputConfig{
		Label:       "Protocol",
		Required:    true,
		Help:        "Path to TLS certificate",
		Placeholder: "/path/to/cert",
	}

	tlsKey := textinputs.InputConfig{
		Label:       "Protocol",
		Required:    true,
		Help:        "Path to TLS key",
		Placeholder: "/path/to/key",
	}

	format := textinputs.InputConfig{
		Label:       "Log format",
		Required:    true,
		Help:        "Can be rfc3164 or rfc5424",
		Placeholder: "rfc3164",
	}

	return textinputs.New([]textinputs.InputConfig{listenAddress, protocol, tlsCert, tlsKey, format})
}

func GetNote() string {
	return ""
}
