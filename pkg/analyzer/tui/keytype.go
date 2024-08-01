package tui

import (
	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/components/confirm"
)

type KeyTypePage struct {
	Common common.Common
}

func (KeyTypePage) Init() tea.Cmd {
	return nil
}

func (ui KeyTypePage) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	keyMsg, ok := msg.(tea.KeyMsg)
	if !ok {
		return ui, nil
	}
	if key.Matches(keyMsg, ui.Common.KeyMap.Back) {
		return confirm.New(ui.Common, "Quit?",
			confirm.WithDefault(true),
			confirm.WithNegativeTransition(ui, nil),
			confirm.WithAffirmativeTransition(nil, tea.Quit),
		), nil
	}
	return ui, nil
}

func (KeyTypePage) View() string {
	return "keytype"
}

func (ui KeyTypePage) NextPage(keyType string) (tea.Model, tea.Cmd) {
	return FormPage{
		Common:  ui.Common,
		KeyType: keyType,
	}, SetKeyTypeCmd(keyType)
}
