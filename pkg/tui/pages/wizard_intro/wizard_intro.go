package wizard_intro

import (
	"strings"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/styles"
)

var (
	wizardIntroChoices = []string{
		"Scan a source using wizard",
		"Scan a source with config",
		"View open-source project",
		"Inquire about Trufflehog Enterprise",
		"Quit",
	}
)

type WizardIntro struct {
	common.Common
	cursor int
	action string
}

func New(c common.Common) *WizardIntro {
	return &WizardIntro{Common: c}
}

func (m *WizardIntro) Init() tea.Cmd {
	return nil
}

func (m *WizardIntro) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q", "esc":
			return m, tea.Quit

		case "enter":
			if wizardIntroChoices[m.cursor] == "Quit" {
				return m, tea.Quit
			}
			m.action = wizardIntroChoices[m.cursor]
			m.cursor = 0

		case "down", "j":
			m.cursor++
			if m.cursor >= len(wizardIntroChoices) {
				m.cursor = 0
			}

		case "up", "k":
			m.cursor--
			if m.cursor < 0 {
				m.cursor = len(wizardIntroChoices) - 1
			}
		}
	}

	return m, nil
}

func (m *WizardIntro) View() string {
	s := strings.Builder{}
	s.WriteString("What do you want to do?\n\n")

	for i := 0; i < len(wizardIntroChoices); i++ {
		if m.cursor == i {
			selectedStyle := lipgloss.NewStyle().Foreground(lipgloss.Color(styles.Colors["sprout"]))
			s.WriteString(selectedStyle.Render(" (•) " + wizardIntroChoices[i]))
		} else {
			s.WriteString(" ( ) " + wizardIntroChoices[i])
		}

		s.WriteString("\n")
	}

	return styles.AppStyle.Render(s.String())
}

func (m *WizardIntro) ShortHelp() []key.Binding {
	// TODO: actually return something
	return nil
}

func (m *WizardIntro) FullHelp() [][]key.Binding {
	// TODO: actually return something
	return nil
}
