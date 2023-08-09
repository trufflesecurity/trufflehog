package source_configure

import (
	"strings"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/styles"
)

type TrufflehogComponent struct {
	common.Common
	parent *SourceConfigure
	form   tea.Model
}

func NewTrufflehogComponent(common common.Common, parent *SourceConfigure) *TrufflehogComponent {
	return &TrufflehogComponent{
		Common: common,
		parent: parent,
	}
}

func (m *TrufflehogComponent) SetForm(form tea.Model) {
	m.form = form
}

func (m *TrufflehogComponent) Init() tea.Cmd {
	return nil
}

func (m *TrufflehogComponent) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	// TODO: Add a focus variable.
	if m.form != nil {
		model, cmd := m.form.Update(msg)
		m.form = model

		return m, cmd
	}
	return m, nil
}

func (m *TrufflehogComponent) View() string {
	var view strings.Builder

	view.WriteString(styles.BoldTextStyle.Render("\nConfiguring "+styles.PrimaryTextStyle.Render("TruffleHog")) + "\n")
	view.WriteString(styles.HintTextStyle.Render("You can skip this completely and run with defaults") + "\n\n")

	if m.form != nil {
		view.WriteString(m.form.View())
		view.WriteString("\n")
	}

	return view.String()
}

func (m *TrufflehogComponent) ShortHelp() []key.Binding {
	// TODO: actually return something
	return nil
}

func (m *TrufflehogComponent) FullHelp() [][]key.Binding {
	// TODO: actually return something
	return nil
}
