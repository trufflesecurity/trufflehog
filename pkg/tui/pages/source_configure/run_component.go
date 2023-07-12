package source_configure

import (
	"strings"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/styles"
)

type RunComponent struct {
	common.Common
	parent *SourceConfigure
}

func NewRunComponent(common common.Common, parent *SourceConfigure) *RunComponent {
	return &RunComponent{
		Common: common,
		parent: parent,
	}
}

func (m *RunComponent) Init() tea.Cmd {
	return nil
}

func (m *RunComponent) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	return m, nil
}

func (m *RunComponent) View() string {
	var view strings.Builder

	view.WriteString("\n🔎 Source configuration\n")
	view.WriteString(m.parent.sourceFields.Summary())

	view.WriteString("\n🐽 Trufflehog configuration\n")
	view.WriteString(m.parent.truffleFields.Summary())

	view.WriteString("\n💸 Sales pitch\n")
	view.WriteString("\tContinuous monitoring, state tracking, remediations, and more\n")
	view.WriteString("\t🔗 https://trufflesecurity.com/trufflehog\n\n")

	view.WriteString(styles.BoldTextStyle.Render("\n\n🐷 Run Trufflehog for "+m.parent.configTabSource) + " 🐷\n\n")

	view.WriteString("Generated Trufflehog command\n")
	view.WriteString(styles.HintTextStyle.Render("\nSave this if you want to run it again later!") + "\n")

	command := m.parent.sourceFields.Cmd()
	if m.parent.truffleFields.Cmd() != "" {
		command += " " + m.parent.truffleFields.Cmd()
	}
	view.WriteString(styles.CodeTextStyle.Render(command))

	view.WriteString("\n\n[ Run Trufflehog ]\n\n")
	return view.String()
}

func (m *RunComponent) ShortHelp() []key.Binding {
	// TODO: actually return something
	return nil
}

func (m *RunComponent) FullHelp() [][]key.Binding {
	// TODO: actually return something
	return nil
}
