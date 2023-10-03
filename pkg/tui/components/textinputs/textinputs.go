package textinputs

// from https://github.com/charmbracelet/bubbletea/blob/master/examples/textinputs/main.go

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	focusedStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))
	blurredStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	noStyle      = lipgloss.NewStyle()
	helpStyle    = blurredStyle.Copy()
	// cursorStyle         = focusedStyle.Copy()
	// cursorModeHelpStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))

	focusedButton     = focusedStyle.Copy().Render("[ Next ]")
	blurredButton     = fmt.Sprintf("[ %s ]", blurredStyle.Render("Next"))
	focusedSkipButton = lipgloss.NewStyle().Foreground(lipgloss.Color("205")).Render("[ Run with defaults ]")
	blurredSkipButton = fmt.Sprintf("[ %s ]", lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Render("Run with defaults"))
)

// SelectNextMsg used for emitting events when the 'Next' button is selected.
type SelectNextMsg int

// SelectSkipMsg used for emitting events when the 'Skip' button is selected.
type SelectSkipMsg int

type Model struct {
	focusIndex int
	inputs     []textinput.Model
	configs    []InputConfig
	// cursorMode cursor.Mode
	skipButton bool
}

type InputConfig struct {
	Label       string
	Key         string
	Help        string
	Required    bool
	Placeholder string
}

type Input struct {
	Value     string
	IsDefault bool
}

func (m Model) GetInputs() map[string]Input {
	inputs := make(map[string]Input)

	for i, input := range m.inputs {
		isDefault := false
		value := input.Value()
		if value == "" && m.configs[i].Required {
			isDefault = true
			value = input.Placeholder
		}
		inputs[m.configs[i].Key] = Input{Value: value, IsDefault: isDefault}
	}

	return inputs
}

func (m Model) GetLabels() map[string]string {
	labels := make(map[string]string)

	for _, config := range m.configs {
		labels[config.Key] = config.Label
	}

	return labels
}

func New(config []InputConfig) Model {
	m := Model{
		inputs: make([]textinput.Model, len(config)),
	}

	for i, conf := range config {
		input := textinput.New()
		input.Placeholder = conf.Placeholder

		if i == 0 {
			input.Focus()
			input.TextStyle = focusedStyle
			input.PromptStyle = focusedStyle
		}

		m.inputs[i] = input
	}

	m.configs = config
	return m
}

func (m Model) Init() tea.Cmd {
	return textinput.Blink
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		// Set focus to next input
		case "enter", "up", "down":
			s := msg.String()

			// Did the user press enter while the submit or skip button was focused?
			// If so, emit the appropriate command.
			if s == "enter" && m.focusIndex == len(m.inputs) {
				return m, func() tea.Msg { return SelectNextMsg(0) }
			} else if s == "enter" && m.focusIndex == -1 {
				return m, func() tea.Msg { return SelectSkipMsg(0) }
			}

			// Cycle indexes
			if s == "up" {
				m.focusIndex--
			} else {
				m.focusIndex++
			}

			if m.focusIndex > len(m.inputs) {
				m.focusIndex = 0
			} else if !m.skipButton && m.focusIndex < 0 {
				m.focusIndex = len(m.inputs)
			} else if m.skipButton && m.focusIndex < -1 {
				m.focusIndex = len(m.inputs)
			}

			cmds := make([]tea.Cmd, len(m.inputs))
			for i := 0; i < len(m.inputs); i++ {
				if i == m.focusIndex {
					// Set focused state
					cmds[i] = m.focusInput(i)
					continue
				}
				// Remove focused state
				m.unfocusInput(i)
			}

			return m, tea.Batch(cmds...)
		}
	}

	// Handle character input and blinking
	cmd := m.updateInputs(msg)

	return m, cmd
}

func (m *Model) updateInputs(msg tea.Msg) tea.Cmd {
	cmds := make([]tea.Cmd, len(m.inputs))

	// Only text inputs with Focus() set will respond, so it's safe to simply
	// update all of them here without any further logic.
	for i := range m.inputs {
		m.inputs[i], cmds[i] = m.inputs[i].Update(msg)
	}

	return tea.Batch(cmds...)
}

func (m Model) View() string {
	var b strings.Builder

	if m.skipButton {
		button := &blurredSkipButton
		if m.focusIndex == -1 {
			button = &focusedSkipButton
		}
		fmt.Fprintf(&b, "%s\n\n\n", *button)
	}

	for i := range m.inputs {
		if m.configs[i].Label != "" {
			b.WriteString(m.GetLabel(m.configs[i]))
		}

		b.WriteString(m.inputs[i].View())
		b.WriteRune('\n')
		if i < len(m.inputs)-1 {
			b.WriteRune('\n')
		}
	}

	button := &blurredButton
	if m.focusIndex == len(m.inputs) {
		button = &focusedButton
	}
	fmt.Fprintf(&b, "\n\n%s\n\n", *button)

	return b.String()
}

func (m Model) GetLabel(c InputConfig) string {
	var label strings.Builder

	label.WriteString(c.Label)
	if c.Required {
		label.WriteString("*")
	}

	if len(c.Help) > 0 {
		label.WriteString("\n" + helpStyle.Render(c.Help))
	}

	label.WriteString("\n")
	return label.String()
}

func (m Model) SetSkip(skip bool) Model {
	m.skipButton = skip
	if m.skipButton {
		if len(m.inputs) > 0 {
			m.unfocusInput(0)
		}
		m.focusIndex = -1
	}
	return m
}

func (m *Model) unfocusInput(index int) {
	m.inputs[index].Blur()
	m.inputs[index].PromptStyle = noStyle
	m.inputs[index].TextStyle = noStyle
}

func (m *Model) focusInput(index int) tea.Cmd {
	m.inputs[index].PromptStyle = focusedStyle
	m.inputs[index].TextStyle = focusedStyle
	return m.inputs[index].Focus()
}
