package tui

import (
	"fmt"
	"os"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

var choices = []string{"Scan a source using wizard", "Scan a source with config", "View open-source project", "Inquire about Trufflehog Enterprise"}

type startModel struct {
	cursor int
	choice string
}

func (m startModel) Init() tea.Cmd {
	return nil
}

func (m startModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q", "esc":
			return m, tea.Quit

		case "enter":
			// Send the choice on the channel and exit.
			m.choice = choices[m.cursor]
			return m, tea.Quit

		case "down", "j":
			m.cursor++
			if m.cursor >= len(choices) {
				m.cursor = 0
			}

		case "up", "k":
			m.cursor--
			if m.cursor < 0 {
				m.cursor = len(choices) - 1
			}
		}
	}

	return m, nil
}

func (m startModel) View() string {
	s := strings.Builder{}
	s.WriteString("What do you want to do?\n\n")

	for i := 0; i < len(choices); i++ {
		if m.cursor == i {
			s.WriteString("(•) ")
		} else {
			s.WriteString("( ) ")
		}
		s.WriteString(choices[i])
		s.WriteString("\n")
	}
	// s.WriteString("\n(press q to quit)\n")

	return s.String()
}

func (model startModel) Run() {
	p := tea.NewProgram(model)
	m, err := p.Run()
	if err != nil {
		fmt.Printf("Alas, there's been an error: %v", err)
		os.Exit(1)
	}

	if m, ok := m.(startModel); ok && m.choice != "" {
		switch m.cursor {
		case 0:
			fmt.Printf("Scan a source using wizard\n")
			(&sourceModel{}).Run()
		case 1:
			fmt.Println("Scan a source with config")
		case 2:
			fmt.Println("https://github.com/trufflesecurity/trufflehog")
		case 3:
			fmt.Println("https://trufflesecurity.com/contact")
		default:
			fmt.Println("Invalid choice")
		}
	}
}
