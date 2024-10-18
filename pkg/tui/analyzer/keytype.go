package tui

import (
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/styles"
)

var (
	selectedItemStyle = lipgloss.NewStyle().
				Border(lipgloss.NormalBorder(), false, false, false, true).
				BorderForeground(lipgloss.AdaptiveColor{Dark: styles.Colors["sprout"], Light: styles.Colors["bronze"]}).
				Foreground(lipgloss.AdaptiveColor{Dark: styles.Colors["sprout"], Light: styles.Colors["fern"]}).
				Padding(0, 0, 0, 1)

	titleStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFFDF5")).
			Background(lipgloss.Color(styles.Colors["bronze"])).
			Padding(0, 1)
)

type KeyTypePage struct {
	Common *common.Common

	list list.Model
}

func (ui KeyTypePage) Init() tea.Cmd {
	return nil
}

func NewKeyTypePage(c *common.Common) KeyTypePage {
	items := make([]list.Item, len(analyzers.AvailableAnalyzers()))
	for i, analyzerType := range analyzers.AvailableAnalyzers() {
		items[i] = KeyTypeItem(analyzerType)
	}
	delegate := list.NewDefaultDelegate()
	delegate.ShowDescription = false
	delegate.SetSpacing(0)
	delegate.Styles.SelectedTitle = selectedItemStyle

	list := list.New(items, delegate, c.Width, c.Height)
	list.Title = "Select an analyzer type"
	list.SetShowStatusBar(false)
	list.Styles.Title = titleStyle
	return KeyTypePage{
		Common: c,
		list:   list,
	}
}

func (ui KeyTypePage) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if !ui.list.SettingFilter() {
		switch msg := msg.(type) {
		case tea.KeyMsg:
			switch {
			case key.Matches(msg, ui.Common.KeyMap.Back):
				return nil, tea.Quit
			case key.Matches(msg, ui.Common.KeyMap.Select):
				chosen := string(ui.list.SelectedItem().(KeyTypeItem))
				return NewFormPage(ui.Common, chosen), SetKeyTypeCmd(chosen)
			}
		}
	}

	var cmd tea.Cmd
	ui.list, cmd = ui.list.Update(msg)
	return ui, cmd
}

func (ui KeyTypePage) View() string {
	return styles.AppStyle.Render(ui.list.View())
}

func (ui KeyTypePage) NextPage(keyType string) (tea.Model, tea.Cmd) {
	return NewFormPage(ui.Common, keyType), SetKeyTypeCmd(keyType)
}

type KeyTypeItem string

func (i KeyTypeItem) ID() string          { return string(i) }
func (i KeyTypeItem) Title() string       { return string(i) }
func (i KeyTypeItem) Description() string { return "" }
func (i KeyTypeItem) FilterValue() string { return string(i) }

func init() {
	// Preload HasDarkBackground call. For some reason, if we don't do
	// this, the TUI can take a noticeably long time to start. We should
	// investigate further, but this is a good-enough bandaid for now.
	// See: https://github.com/charmbracelet/lipgloss/issues/73
	_ = lipgloss.HasDarkBackground()
}
