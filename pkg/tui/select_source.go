package tui

import (
	"fmt"
	"os"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/sources"
)

type sourceModel struct {
	cursor  int
	choice  string
	choices []string
}

func (m *sourceModel) Init() tea.Cmd {
	var sourceChoices = sources.SourceChoices
	m.choices = sourceChoices
	return nil
}

func (m *sourceModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q", "esc":
			return m, tea.Quit

		case "enter":
			// Send the choice on the channel and exit.
			m.choice = m.choices[m.cursor]
			return m, tea.Quit

		case "down", "j":
			m.cursor++
			if m.cursor >= len(m.choices) {
				m.cursor = 0
			}

		case "up", "k":
			m.cursor--
			if m.cursor < 0 {
				m.cursor = len(m.choices) - 1
			}
		}
	}

	return m, nil
}

func (m *sourceModel) View() string {
	s := strings.Builder{}
	s.WriteString("What data source do you want to scan from?\n\n")

	for i := 0; i < len(m.choices); i++ {
		if m.cursor == i {
			s.WriteString("(•) ")
		} else {
			s.WriteString("( ) ")
		}
		s.WriteString(m.choices[i])
		s.WriteString("\n")
	}
	s.WriteString("\nInterested in Enterprise? Scan additional sources like Slack, JIRA, Artifactory, Buildkite, etc.\nReach out to us at https://trufflesecurity.com/contact\n\n")

	return s.String()
}

func (model *sourceModel) Run() {
	p := tea.NewProgram(model)
	m, err := p.Run()
	if err != nil {
		fmt.Printf("Alas, there's been an error: %v", err)
		os.Exit(1)
	}

	if m, ok := m.(*sourceModel); ok && m.choice != "" {
		sources.Run(m.choice)
	}
}
