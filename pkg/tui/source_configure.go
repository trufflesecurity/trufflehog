package tui

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"gopkg.in/alecthomas/kingpin.v2"
)

type sourceConfigureModel struct {
	cmd *kingpin.CmdModel
}

func (m sourceConfigureModel) Init() tea.Cmd {
	return nil
}

func (m sourceConfigureModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	return m, tea.Quit
}

func (m sourceConfigureModel) View() string {
	if m.cmd == nil {
		return "no source selected"
	}
	var sb strings.Builder
	for _, arg := range m.cmd.Args {
		if arg.Required {
			sb.WriteString("*** ")
		}
		sb.WriteString(arg.Name + "    " + arg.Help + "\n")
	}
	for _, flag := range m.cmd.Flags {
		if strings.Contains(flag.Name, "help") ||
			strings.Contains(flag.Name, "completion") ||
			strings.Contains(flag.Help, "No-op") {
			continue
		}
		if flag.Required {
			sb.WriteString("*** ")
		}
		sb.WriteString("--" + flag.Name + " " + flag.Help + "\n")
	}
	return sb.String()
}
