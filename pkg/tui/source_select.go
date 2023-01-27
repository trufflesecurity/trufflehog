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

type sourceSelectModel struct {
	sourcesList  list.Model
	keys         *listKeyMap
	delegateKeys *delegateKeyMap
}

func newSourceSelectModel() sourceSelectModel {
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
		item{"Git", "Scan git repositories."},
		item{"GitHub", "Scan Github repositories and/or organizations."},
		item{"GitLab", "Scan GitLab repositories."},
		item{"Filesystem", "Scan your filesystem by selecting what directories to scan."},
		item{"AWS S3", "Scan Amazon S3 buckets."},
		item{"CircleCI", "Scan CircleCI, a CI/CD platform."},
		item{"Syslog", "Scan syslog, event data logs."},
		// Enterprise sources.
		item{"⭐ Artifactory", "Scan JFrog Artifactory packages. (Enterprise only)"},
		item{"⭐ BitBucket", "Scan Atlassian's Git-based source code repository hosting service. (Enterprise only)"},
		item{"⭐ Buildkite", "Scan Buildkite, a CI/CD platform. (Enterprise only)"},
		item{"⭐ Confluence", "Scan Atlassian's web-based wiki and knowledge base. (Enterprise only)"},
		item{"⭐ Gerrit", "Scan Gerrit, a code collaboration tool (Enterprise only)"},
		item{"⭐ Jenkins ", "Scan Jenkins, a CI/CD platform. (Enterprise only)"},
		item{"⭐ Jira", "Scan Atlassian's issue & project tracking software. (Enterprise only)"},
		item{"⭐ Slack", "Scan Slack, a messaging and communication platform. (Enterprise only)"},
		item{"⭐ Microsoft Teams", "Scan Microsoft Teams, a messaging and communication platform. (Enterprise only)"},
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

	return sourceSelectModel{
		sourcesList:  sourcesList,
		keys:         listKeys,
		delegateKeys: delegateKeys,
	}
}

func (m sourceSelectModel) Init() tea.Cmd {
	return nil
}

func (m sourceSelectModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
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

func (m sourceSelectModel) View() string {
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
