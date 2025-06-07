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
	helpStyle    = blurredStyle
	// cursorStyle         = focusedStyle.
	// cursorModeHelpStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))

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
	submitMsg  string
	header     string
	footer     string
}

type InputConfig struct {
	Label       string
	Key         string
	Help        string
	Required    bool
	Placeholder string
	RedactInput bool
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
		inputs:    make([]textinput.Model, len(config)),
		submitMsg: "Next",
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

	if m.header != "" {
		fmt.Fprintf(&b, "%s\n\n", m.header)
	}

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

		input := m.inputs[i]
		if val := input.Value(); len(val) > 4 && m.configs[i].RedactInput {
			if len(val) > 10 {
				// start***end
				input.SetValue(val[:4] + strings.Repeat("*", len(val)-8) + val[len(val)-4:])
			} else {
				// start***
				input.SetValue(val[:4] + strings.Repeat("*", len(val)-4))
			}
		}
		b.WriteString(input.View())
		b.WriteRune('\n')
		if i < len(m.inputs)-1 {
			b.WriteRune('\n')
		}
	}

	if m.footer != "" {
		fmt.Fprintf(&b, "\n\n%s", m.footer)
	}

	button := blurredStyle.Render(m.submitMsg)
	if m.focusIndex == len(m.inputs) {
		button = focusedStyle.Render(fmt.Sprintf("[ %s ]", m.submitMsg))
	}
	fmt.Fprintf(&b, "\n\n%s\n\n", button)

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

func (m Model) SetSubmitMsg(msg string) Model {
	m.submitMsg = msg
	return m
}

func (m Model) SetFooter(foot string) Model {
	m.footer = foot
	return m
}

func (m Model) SetHeader(head string) Model {
	m.header = head
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
