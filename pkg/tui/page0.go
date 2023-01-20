package tui

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

var (
	page0Choices = []string{
		"Scan a source using wizard",
		"Scan a source with config",
		"View open-source project",
		"Inquire about Trufflehog Enterprise",
	}
)

type page0Model struct {
	cursor int
	action string
}

func (m page0Model) Init() tea.Cmd {
	return nil
}

func (m page0Model) Update(msg tea.Msg) (page0Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q", "esc":
			return m, tea.Quit

		case "enter":
			// Move to the next state.
			m.action = page0Choices[m.cursor]
			m.cursor = 0

		case "down", "j":
			m.cursor++
			if m.cursor >= len(page0Choices) {
				m.cursor = 0
			}

		case "up", "k":
			m.cursor--
			if m.cursor < 0 {
				m.cursor = len(page0Choices) - 1
			}
		}
	}

	return m, nil
}

func (m page0Model) View() string {
	s := strings.Builder{}
	s.WriteString("What do you want to do?\n\n")

	for i := 0; i < len(page0Choices); i++ {
		if m.cursor == i {
			s.WriteString(" (•) ")
		} else {
			s.WriteString(" ( ) ")
		}
		s.WriteString(page0Choices[i])
		s.WriteString("\n")
	}

	return appStyle.Render(s.String())
}
