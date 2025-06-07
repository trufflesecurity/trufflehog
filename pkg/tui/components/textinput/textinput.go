package textinput

import (
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

type (
	errMsg error
)

type TextInput struct {
	textInput textinput.Model
	err       error
}

func New(placeholder string) TextInput {
	ti := textinput.New()
	ti.Placeholder = placeholder
	ti.Focus()
	ti.CharLimit = 156
	ti.Width = 60

	return TextInput{
		textInput: ti,
		err:       nil,
	}
}

func (m TextInput) Init() tea.Cmd {
	return textinput.Blink
}

func (m TextInput) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {

	// We handle errors just like any other message
	case errMsg:
		m.err = msg
		return m, nil
	}

	m.textInput, cmd = m.textInput.Update(msg)
	return m, cmd
}

func (m TextInput) View() string {
	return m.textInput.View()
}
