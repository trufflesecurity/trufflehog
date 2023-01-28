package tui

import (
	"time"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// TODO: Review light theme styling
var (
	titleStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFFDF5")).
			Background(lipgloss.Color(colors["bronze"])).
			Padding(0, 1)

	statusMessageStyle = lipgloss.NewStyle().
				Foreground(lipgloss.AdaptiveColor{Dark: colors["sand"], Light: "#13543c"}).
				Render

	// FIXME: Hon pls help
	errorStatusMessageStyle = lipgloss.NewStyle().
				Foreground(lipgloss.AdaptiveColor{Dark: "#ff0000"}).
				Render

	selectedItemStyle = lipgloss.NewStyle().
				Border(lipgloss.NormalBorder(), false, false, false, true).
				BorderForeground(lipgloss.AdaptiveColor{Dark: colors["sprout"], Light: colors["bronze"]}).
				Foreground(lipgloss.AdaptiveColor{Dark: colors["sprout"], Light: colors["fern"]}).
				Padding(0, 0, 0, 1)

	selectedDescription = selectedItemStyle.Copy().
				Foreground(lipgloss.AdaptiveColor{Dark: colors["sprout"], Light: colors["sprout"]})
)

type item struct {
	title        string
	description  string
	isEnterprise bool
}

func (i item) Title() string {
	if i.isEnterprise {
		return "🔒 " + i.title
	}
	return i.title
}
func (i item) Description() string {
	if i.isEnterprise {
		return i.description + " (Enterprise only)"
	}
	return i.description
}

func (i item) FilterValue() string { return i.title + i.description }

type listKeyMap struct {
	toggleHelpMenu key.Binding
}

type (
	sourceSelectModel struct {
		sourcesList  list.Model
		keys         *listKeyMap
		delegateKeys *delegateKeyMap
	}
	sourceSelectMsg struct {
		selection string
	}
)

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
		item{"Git", "Scan git repositories.", false},
		item{"GitHub", "Scan GitHub repositories and/or organizations.", false},
		item{"GitLab", "Scan GitLab repositories.", false},
		item{"Filesystem", "Scan your filesystem by selecting what directories to scan.", false},
		item{"AWS S3", "Scan Amazon S3 buckets.", false},
		item{"CircleCI", "Scan CircleCI, a CI/CD platform.", false},
		item{"Syslog", "Scan syslog, event data logs.", false},
		// Enterprise sources.
		item{"Artifactory", "Scan JFrog Artifactory packages.", true},
		item{"BitBucket", "Scan Atlassian's Git-based source code repository hosting service.", true},
		item{"Buildkite", "Scan Buildkite, a CI/CD platform.", true},
		item{"Confluence", "Scan Atlassian's web-based wiki and knowledge base.", true},
		item{"Gerrit", "Scan Gerrit, a code collaboration tool", true},
		item{"Jenkins ", "Scan Jenkins, a CI/CD platform.", true},
		item{"Jira", "Scan Atlassian's issue & project tracking software.", true},
		item{"Slack", "Scan Slack, a messaging and communication platform.", true},
		item{"Microsoft Teams", "Scan Microsoft Teams, a messaging and communication platform.", true},
	}

	// Setup list
	delegate := newItemDelegate(delegateKeys)
	delegate.Styles.SelectedTitle = selectedItemStyle
	delegate.Styles.SelectedDesc = selectedDescription

	sourcesList := list.New(items, delegate, 0, 0)
	sourcesList.Title = "Sources"
	sourcesList.Styles.Title = titleStyle
	sourcesList.StatusMessageLifetime = 10 * time.Second
	// sourcesList.Styles.FilterCursor = filterCursorStyle

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
		var selectedItem item

		if i, ok := m.SelectedItem().(item); ok {
			selectedItem = i

		} else {
			return nil
		}

		if msg, ok := msg.(tea.KeyMsg); ok && key.Matches(msg, keys.choose) {
			if selectedItem.isEnterprise {
				return m.NewStatusMessage(errorStatusMessageStyle(
					"That's an enterprise only source. Learn more at trufflesecurity.com",
				))
			}

			return func() tea.Msg { return sourceSelectMsg{selectedItem.title} }
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
