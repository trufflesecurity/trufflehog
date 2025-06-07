package syslog

import (
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/components/textinputs"
)

type syslogCmdModel struct {
	textinputs.Model
}

// TODO: review fields
func GetFields() syslogCmdModel {
	protocol := textinputs.InputConfig{
		Label:       "Protocol",
		Key:         "protocol",
		Required:    true,
		Help:        "udp or tcp",
		Placeholder: "tcp",
	}

	listenAddress := textinputs.InputConfig{
		Label:       "Address",
		Key:         "address",
		Help:        "Address and port to listen on for syslog",
		Required:    true,
		Placeholder: "127.0.0.1:514",
	}

	tlsCert := textinputs.InputConfig{
		Label:       "TLS Certificate",
		Key:         "cert",
		Required:    true,
		Help:        "Path to TLS certificate",
		Placeholder: "/path/to/cert",
	}

	tlsKey := textinputs.InputConfig{
		Label:       "TLS Key",
		Key:         "key",
		Required:    true,
		Help:        "Path to TLS key",
		Placeholder: "/path/to/key",
	}

	format := textinputs.InputConfig{
		Label:       "Log format",
		Key:         "format",
		Required:    true,
		Help:        "Can be rfc3164 or rfc5424",
		Placeholder: "rfc3164",
	}

	return syslogCmdModel{textinputs.New([]textinputs.InputConfig{listenAddress, protocol, tlsCert, tlsKey, format})}
}

func (m syslogCmdModel) Cmd() string {
	var command []string
	command = append(command, "trufflehog", "syslog")

	inputs := m.GetInputs()
	syslogKeys := [5]string{"address", "protocol", "cert", "key", "format"}

	for _, key := range syslogKeys {
		flag := "--" + key + "=" + inputs[key].Value
		command = append(command, flag)
	}

	return strings.Join(command, " ")
}

func (m syslogCmdModel) Summary() string {
	inputs := m.GetInputs()
	labels := m.GetLabels()
	keys := []string{"address", "protocol", "cert", "key", "format"}

	return common.SummarizeSource(keys, inputs, labels)
}
