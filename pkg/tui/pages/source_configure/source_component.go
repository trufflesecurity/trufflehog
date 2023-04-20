package source_configure

import (
	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/common"
)

type SourceComponent struct {
	common.Common
}

func NewSourceComponent(common common.Common) *SourceComponent {
	return &SourceComponent{
		Common: common,
	}
}

func (m *SourceComponent) Init() tea.Cmd {
	return nil
}

func (m *SourceComponent) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	return m, nil
}

func (m *SourceComponent) View() string {
	return "source view component"
}

func (m *SourceComponent) ShortHelp() []key.Binding {
	// TODO: actually return something
	return nil
}

func (m *SourceComponent) FullHelp() [][]key.Binding {
	// TODO: actually return something
	return nil
}
