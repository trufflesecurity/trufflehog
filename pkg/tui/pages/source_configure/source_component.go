package source_configure

import (
	"strings"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/styles"
)

type SourceComponent struct {
	common.Common
	parent *SourceConfigure
	form   tea.Model
}

func NewSourceComponent(common common.Common, parent *SourceConfigure) *SourceComponent {
	return &SourceComponent{
		Common: common,
		parent: parent,
	}
}

func (m *SourceComponent) SetForm(form tea.Model) {
	m.form = form
}

func (m *SourceComponent) Init() tea.Cmd {
	return nil
}

func (m *SourceComponent) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	// TODO: Add a focus variable.
	if m.form != nil {
		model, cmd := m.form.Update(msg)
		m.form = model
		return m, cmd
	}
	return m, nil
}

func (m *SourceComponent) View() string {
	var view strings.Builder

	view.WriteString(styles.BoldTextStyle.Render("\nConfiguring "+styles.PrimaryTextStyle.Render(m.parent.configTabSource)) + "\n")

	view.WriteString(styles.HintTextStyle.Render("* required field") + "\n\n")

	sourceNote := sources.GetSourceNotes(m.parent.configTabSource)
	if len(sourceNote) > 0 {
		view.WriteString("⭐ " + sourceNote + " ⭐\n\n")
	}

	if m.form != nil {
		view.WriteString(m.form.View())
		view.WriteString("\n")
	}
	return view.String()
}

func (m *SourceComponent) ShortHelp() []key.Binding {
	// TODO: actually return something
	return nil
}

func (m *SourceComponent) FullHelp() [][]key.Binding {
	// TODO: actually return something
	return nil
}
