package tui

import (
	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/common"
)

type FormPage struct {
	Common  common.Common
	KeyType string
}

func (FormPage) Init() tea.Cmd {
	return nil
}

func (ui FormPage) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	// TODO: Check form focus.
	if msg, ok := msg.(tea.KeyMsg); ok {
		switch {
		case key.Matches(msg, ui.Common.KeyMap.Back):
			return ui.PrevPage()
		}
	}
	return ui, nil
}

func (ui FormPage) View() string {
	return ui.KeyType
}

func (ui FormPage) PrevPage() (tea.Model, tea.Cmd) {
	return KeyTypePage{Common: ui.Common}, nil
}
