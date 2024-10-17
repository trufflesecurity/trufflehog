package contact_enterprise

import (
	"strings"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/styles"
)

type ContactEnterprise struct {
	common.Common
	viewed bool
}

var (
	linkStyle = lipgloss.NewStyle().Foreground(
		lipgloss.Color("28")) // green
)

func New(c common.Common) *ContactEnterprise {
	return &ContactEnterprise{
		Common: c,
		viewed: false,
	}
}

func (m *ContactEnterprise) Init() tea.Cmd {
	return nil
}

func (m *ContactEnterprise) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if m.viewed {
		return m, tea.Quit
	}

	return m, func() tea.Msg { return nil }
}

func (m *ContactEnterprise) View() string {

	s := strings.Builder{}
	s.WriteString("Interested in TruffleHog enterprise?\n")
	s.WriteString(linkStyle.Render("🔗 https://trufflesecurity.com/contact"))

	m.viewed = true
	return styles.AppStyle.Render(s.String())
}

func (m *ContactEnterprise) ShortHelp() []key.Binding {
	// TODO: actually return something
	return nil
}

func (m *ContactEnterprise) FullHelp() [][]key.Binding {
	// TODO: actually return something
	return nil
}
