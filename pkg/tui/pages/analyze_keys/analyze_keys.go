package analyze_keys

import (
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/components/selector"
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
	if !ui.list.SettingFilter() {
		switch msg := msg.(type) {

		case tea.WindowSizeMsg:
			h, v := styles.AppStyle.GetFrameSize()
			ui.list.SetSize(msg.Width-h, msg.Height-v)
		case tea.KeyMsg:
			switch {
			case key.Matches(msg, ui.Common.KeyMap.Back):
				return nil, tea.Quit
			case key.Matches(msg, ui.Common.KeyMap.Select):
				chosenAnalyzer := ui.list.SelectedItem().(KeyTypeItem)

				return ui, func() tea.Msg {
					return selector.SelectMsg{IdentifiableItem: chosenAnalyzer}
				}
			}
		}

		var cmd tea.Cmd
		ui.list, cmd = ui.list.Update(msg)
		return ui, cmd
	}
	return ui, func() tea.Msg { return nil }
}

func (ui AnalyzeKeyPage) View() string {
	return styles.AppStyle.Render(ui.list.View())
}

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
