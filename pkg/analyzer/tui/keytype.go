package tui

import (
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/components/confirm"
)

type KeyTypePage struct {
	Common *common.Common

	list list.Model
}

func (ui KeyTypePage) Init() tea.Cmd {
	return nil
}

func NewKeyTypePage(c *common.Common) KeyTypePage {
	items := make([]list.Item, len(analyzers.AvailableAnalyzers))
	for i, analyzerType := range analyzers.AvailableAnalyzers {
		items[i] = KeyTypeItem{KeyType: analyzerType}
	}
	delegate := list.NewDefaultDelegate()
	delegate.ShowDescription = false
	delegate.SetSpacing(0)

	list := list.New(items, delegate, c.Width, c.Height)
	list.Title = "Select an analyzer type"
	return KeyTypePage{
		Common: c,
		list:   list,
	}
}

func (ui KeyTypePage) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch {
		case key.Matches(msg, ui.Common.KeyMap.Back):
			return confirm.New(*ui.Common, "Quit?",
				confirm.WithDefault(true),
				confirm.WithNegativeTransition(ui, nil),
				confirm.WithAffirmativeTransition(nil, tea.Quit),
			), nil
		case key.Matches(msg, ui.Common.KeyMap.Select):
			chosen := ui.list.SelectedItem().(KeyTypeItem)
			return FormPage{
				Common:  ui.Common,
				KeyType: chosen.KeyType,
			}, nil
		}
	}

	var cmd tea.Cmd
	ui.list, cmd = ui.list.Update(msg)
	return ui, cmd
}

func (ui KeyTypePage) View() string {
	return ui.list.View()
}

func (ui KeyTypePage) NextPage(keyType string) (tea.Model, tea.Cmd) {
	return FormPage{
		Common:  ui.Common,
		KeyType: keyType,
	}, SetKeyTypeCmd(keyType)
}

type KeyTypeItem struct {
	KeyType string
}

func (i KeyTypeItem) ID() string          { return i.KeyType }
func (i KeyTypeItem) Title() string       { return i.KeyType }
func (i KeyTypeItem) Description() string { return "" }
func (i KeyTypeItem) FilterValue() string { return i.KeyType }
