package tui

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/common"
)

type KeyTypePage struct {
	Common common.Common
}

func (KeyTypePage) Init() tea.Cmd {
	return nil
}

func (ui KeyTypePage) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if key, ok := msg.(tea.KeyMsg); ok && key.String() == "g" {
		return ui.NextPage("github")
	}
	return ui, nil
}

func (KeyTypePage) View() string {
	return ""
}

func (ui KeyTypePage) NextPage(keyType string) (tea.Model, tea.Cmd) {
	return FormPage{
		Common:  ui.Common,
		KeyType: keyType,
	}, SetKeyTypeCmd(keyType)
}
