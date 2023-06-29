package source_configure

import (
	"strings"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/components/formfield"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/styles"
)

type SourceComponent struct {
	common.Common
	parent *SourceConfigure
	form   []*formfield.FormField
}

func NewSourceComponent(common common.Common, parent *SourceConfigure) *SourceComponent {
	return &SourceComponent{
		Common: common,
		parent: parent,
	}
}

func (m *SourceComponent) SetForm(form []*formfield.FormField) {
	m.form = form
}

func (m *SourceComponent) Init() tea.Cmd {
	return nil
}

func (m *SourceComponent) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	// TODO: Add a focus variable.
	if len(m.form) > 0 {
		model, cmd := m.form[0].Component.Update(msg)
		m.form[0].Component = model
		return m, cmd
	}
	return m, nil
}

func (m *SourceComponent) View() string {
	var view strings.Builder

	view.WriteString(styles.BoldTextStyle.Render("\nConfiguring "+styles.PrimaryTextStyle.Render(m.parent.configTabSource)) + "\n")

	view.WriteString(styles.HintTextStyle.Render("* required field") + "\n")

	for _, form := range m.form {
		view.WriteString("\n")
		view.WriteString(form.Label)
		if form.Required {
			view.WriteString("*")
		}
		view.WriteString("\n")
		view.WriteString(form.Component.View())
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
