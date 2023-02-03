package tui

import (
	"strconv"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"gopkg.in/alecthomas/kingpin.v2"
)

type sourceConfigureModel struct {
	cmd *kingpin.CmdModel
	tbl table.Model
}

func (m sourceConfigureModel) Init() tea.Cmd {
	return nil
}

func (m sourceConfigureModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			// TODO: go back?
			return m, tea.Quit
		case "enter":
			// TODO: popup to set value
			return m, tea.Batch(
				tea.Printf("Let's go to %s!", m.tbl.SelectedRow()[1]),
			)
		}
	}
	m.tbl, cmd = m.tbl.Update(msg)
	return m, cmd
}

func (m sourceConfigureModel) View() string {
	if m.cmd == nil {
		return "no source selected"
	}
	return m.tbl.View()
	// var sb strings.Builder
	// for _, arg := range m.cmd.Args {
	// 	if arg.Required {
	// 		sb.WriteString("*** ")
	// 	}
	// 	sb.WriteString(" {" + strings.Join(arg.Default, "|") + "} ")
	// 	sb.WriteString(" [" + arg.Envar + "] ")
	// 	sb.WriteString(arg.Name + "    " + arg.Help + "\n")
	// }
	// for _, flag := range m.cmd.Flags {
	// 	if strings.Contains(flag.Name, "help") ||
	// 		strings.Contains(flag.Name, "completion") ||
	// 		strings.Contains(flag.Help, "No-op") {
	// 		continue
	// 	}
	// 	if flag.Required {
	// 		sb.WriteString("*** ")
	// 	}
	// 	sb.WriteString(" {" + strings.Join(flag.Default, "|") + "} ")
	// 	sb.WriteString(" [" + flag.Envar + "] ")
	// 	sb.WriteString("--" + flag.Name + " " + flag.Help + "\n")
	// }
	// return sb.String()
}

func newSourceConfigure(cmd *kingpin.CmdModel) sourceConfigureModel {
	columns := []table.Column{
		{Title: "Required", Width: 10},
		{Title: "Name", Width: 20},
		{Title: "Description", Width: 30},
		{Title: "Value", Width: 20},
	}

	var rows []table.Row
	for _, arg := range cmd.Args {
		row := []string{
			strconv.FormatBool(arg.Required),
			arg.Name,
			arg.Help,
			arg.Value.String(),
		}
		rows = append(rows, row)
	}
	for _, flag := range cmd.Flags {
		row := []string{
			strconv.FormatBool(flag.Required),
			flag.Name,
			flag.Help,
			flag.Value.String(),
		}
		rows = append(rows, row)
	}

	tbl := table.New(
		table.WithColumns(columns),
		table.WithRows(rows),
		table.WithFocused(true),
		// table.WithHeight(7),
	)

	s := table.DefaultStyles()
	s.Header = s.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("240")).
		BorderBottom(true).
		Bold(false)
	s.Selected = s.Selected.
		Foreground(lipgloss.Color("229")).
		Background(lipgloss.Color("57")).
		Bold(false)
	// s.Cell = s.Cell.Width(30)
	tbl.SetStyles(s)

	return sourceConfigureModel{
		cmd: cmd,
		tbl: tbl,
	}
}
