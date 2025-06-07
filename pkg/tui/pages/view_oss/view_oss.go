package view_oss

import (
	"strings"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/styles"
)

type ViewOSS struct {
	common.Common
	viewed bool
}

var (
	linkStyle = lipgloss.NewStyle().Foreground(
		lipgloss.Color("28")) // green
)

func New(c common.Common) *ViewOSS {
	return &ViewOSS{
		Common: c,
		viewed: false,
	}
}

func (m *ViewOSS) Init() tea.Cmd {
	return nil
}

func (m *ViewOSS) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if m.viewed {
		return m, tea.Quit
	}

	return m, func() tea.Msg { return nil }
}

func (m *ViewOSS) View() string {
	s := strings.Builder{}
	s.WriteString("View our open-source project on GitHub\n")
	s.WriteString(linkStyle.Render("🔗 https://github.com/trufflesecurity/trufflehog "))

	m.viewed = true
	return styles.AppStyle.Render(s.String())
}

func (m *ViewOSS) ShortHelp() []key.Binding {
	// TODO: actually return something
	return nil
}

func (m *ViewOSS) FullHelp() [][]key.Binding {
	// TODO: actually return something
	return nil
}
