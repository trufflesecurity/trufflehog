package tui

import (
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	titleStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFFDF5")).
			Background(lipgloss.Color("#25A065")).
			Padding(0, 1)

	statusMessageStyle = lipgloss.NewStyle().
				Foreground(lipgloss.AdaptiveColor{Light: "#04B575", Dark: "#04B575"}).
				Render
)

type item struct {
	title       string
	description string
}

func (i item) Title() string       { return i.title }
func (i item) Description() string { return i.description }
func (i item) FilterValue() string { return i.title }

type listKeyMap struct {
	toggleHelpMenu key.Binding
}

type page1Model struct {
	sourcesList  list.Model
	keys         *listKeyMap
	delegateKeys *delegateKeyMap
}

func newPage1Model() page1Model {
	var (
		delegateKeys = newDelegateKeyMap()
		listKeys     = &listKeyMap{
			toggleHelpMenu: key.NewBinding(
				key.WithKeys("H"),
				key.WithHelp("H", "toggle help"),
			),
		}
	)

	// Make list of items.
	items := []list.Item{
		// Open source sources.
		item{"circleci", "Scan circleci."},
		item{"filesystem", "Scan filesystem."},
		item{"git", "Scan git."},
		item{"github", "Scan github."},
		item{"gitlab", "Scan gitlab."},
		item{"s3", "Scan s3."},
		item{"syslog", "Scan syslog."},
		// Enterprise sources.
		item{"artifactory", "Enterprise only source."},
		item{"bitbucket", "Enterprise only source."},
		item{"buildkite", "Enterprise only source."},
		item{"confluence", "Enterprise only source."},
		item{"gerrit", "Enterprise only source."},
		item{"jenkins", "Enterprise only source."},
		item{"jira", "Enterprise only source."},
		item{"slack", "Enterprise only source."},
		item{"teams", "Enterprise only source."},
	}

	// Setup list
	delegate := newItemDelegate(delegateKeys)
	sourcesList := list.New(items, delegate, 0, 0)
	sourcesList.Title = "Sources"
	sourcesList.Styles.Title = titleStyle
	sourcesList.AdditionalFullHelpKeys = func() []key.Binding {
		return []key.Binding{
			listKeys.toggleHelpMenu,
		}
	}
	sourcesList.SetShowStatusBar(false)

	return page1Model{
		sourcesList:  sourcesList,
		keys:         listKeys,
		delegateKeys: delegateKeys,
	}
}

func (m page1Model) Init() tea.Cmd {
	return tea.EnterAltScreen
}

func (m page1Model) Update(msg tea.Msg) (page1Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		h, v := appStyle.GetFrameSize()
		m.sourcesList.SetSize(msg.Width-h, msg.Height-v)

	case tea.KeyMsg:
		// Don't match any of the keys below if we're actively filtering.
		if m.sourcesList.FilterState() == list.Filtering {
			break
		}

		switch {
		case key.Matches(msg, m.keys.toggleHelpMenu):
			m.sourcesList.SetShowHelp(!m.sourcesList.ShowHelp())
			return m, nil
		}
	}

	// This will also call our delegate's update function.
	newListModel, cmd := m.sourcesList.Update(msg)
	m.sourcesList = newListModel
	cmds = append(cmds, cmd)

	return m, tea.Batch(cmds...)
}

func (m page1Model) View() string {
	return appStyle.Render(m.sourcesList.View())
}

func newItemDelegate(keys *delegateKeyMap) list.DefaultDelegate {
	d := list.NewDefaultDelegate()

	d.UpdateFunc = func(msg tea.Msg, m *list.Model) tea.Cmd {
		var title string

		if i, ok := m.SelectedItem().(item); ok {
			title = i.Title()
		} else {
			return nil
		}

		if msg, ok := msg.(tea.KeyMsg); ok && key.Matches(msg, keys.choose) {
			return m.NewStatusMessage(statusMessageStyle("You chose " + title))
		}

		return nil
	}

	help := []key.Binding{keys.choose}
	d.ShortHelpFunc = func() []key.Binding { return help }
	d.FullHelpFunc = func() [][]key.Binding { return [][]key.Binding{help} }

	return d
}

type delegateKeyMap struct {
	choose key.Binding
}

// Additional short help entries. This satisfies the help.KeyMap interface and
// is entirely optional.
func (d delegateKeyMap) ShortHelp() []key.Binding {
	return []key.Binding{d.choose}
}

// Additional full help entries. This satisfies the help.KeyMap interface and
// is entirely optional.
func (d delegateKeyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{{d.choose}}
}

func newDelegateKeyMap() *delegateKeyMap {
	return &delegateKeyMap{
		choose: key.NewBinding(
			key.WithKeys("enter"),
			key.WithHelp("enter", "choose"),
		),
	}
}
