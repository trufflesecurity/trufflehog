package tui

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	wizardIntroChoices = []string{
		"Scan a source using wizard",
		"Scan a source with config",
		"View open-source project",
		"Inquire about Trufflehog Enterprise",
	}
)

type wizardIntroModel struct {
	cursor int
	action string
}

func (m wizardIntroModel) Init() tea.Cmd {
	return nil
}

func (m wizardIntroModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q", "esc":
			return m, tea.Quit

		case "enter":
			// Move to the next state.
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

func (m wizardIntroModel) View() string {
	s := strings.Builder{}
	s.WriteString("What do you want to do?\n\n")

	for i := 0; i < len(wizardIntroChoices); i++ {
		if m.cursor == i {
			selectedStyle := lipgloss.NewStyle().Foreground(lipgloss.Color(colors["sprout"]))
			s.WriteString(selectedStyle.Render(" (•) " + wizardIntroChoices[i]))
		} else {
			s.WriteString(" ( ) " + wizardIntroChoices[i])
		}

		s.WriteString("\n")
	}

	return appStyle.Render(s.String())
}
