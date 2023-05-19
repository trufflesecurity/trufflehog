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

	view.WriteString(styles.BoldTextStyle.Render("\n🐷 Run Trufflehog for "+m.parent.configTabSource) + "🐷\n\n")

	view.WriteString("Generated command: \n")
	view.WriteString(styles.CodeTextStyle.Render("trufflehog github ---org=trufflesecurity"))

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
