package analyze_keys

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

type AnalyzeKeyPage struct {
	common.Common
	list list.Model
}

func (ui *AnalyzeKeyPage) Init() tea.Cmd {
	return nil
}

func New(c common.Common) *AnalyzeKeyPage {
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
	return &AnalyzeKeyPage{
		Common: c,
		list:   list,
	}
}

func (ui *AnalyzeKeyPage) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	// if msg, ok := msg.(tea.WindowSizeMsg); ok {
	// 	ui.SetAnalyzeSize(msg.Width, msg.Height)
	// }

	if !ui.list.SettingFilter() {
		switch msg := msg.(type) {
		case tea.KeyMsg:
			switch {
			case key.Matches(msg, ui.Common.KeyMap.Back):
				return nil, tea.Quit
				// case key.Matches(msg, ui.Common.KeyMap.Select):
				// 	chosen := string(ui.list.SelectedItem().(KeyTypeItem))
				// 	return NewFormPage(ui.Common, chosen), SetKeyTypeCmd(chosen)
				// }
			}
		}

		var cmd tea.Cmd
		ui.list, cmd = ui.list.Update(msg)
		return ui, cmd
	}
	return ui, func() tea.Msg { return nil }
}

// func (ui *AnalyzeKeyPage) SetAnalyzeSize(width, height int) {
// 	h, v := styles.AppStyle.GetFrameSize()
// 	h, v = width-h, height-v
// 	ui.Common.SetSize(h, v)
// 	*ui = New(&ui.Common)
// }

func (ui AnalyzeKeyPage) View() string {
	return styles.AppStyle.Render(ui.list.View())
}

// func (ui AnalyzeKeyPage) NextPage(keyType string) (tea.Model, tea.Cmd) {
// 	return nil
// 	// return NewFormPage(ui.Common, keyType), SetKeyTypeCmd(keyType)
// }

type KeyTypeItem string

func (i KeyTypeItem) ID() string          { return string(i) }
func (i KeyTypeItem) Title() string       { return string(i) }
func (i KeyTypeItem) Description() string { return "" }
func (i KeyTypeItem) FilterValue() string { return string(i) }

func (m AnalyzeKeyPage) ShortHelp() []key.Binding {
	// TODO: actually return something
	return nil
}

func (m AnalyzeKeyPage) FullHelp() [][]key.Binding {
	// TODO: actually return something
	return nil
}
