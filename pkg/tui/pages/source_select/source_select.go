package source_select

import (
	"time"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/components/selector"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/styles"
	"gopkg.in/alecthomas/kingpin.v2"
)

// TODO: Review light theme styling
var (
	titleStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFFDF5")).
			Background(lipgloss.Color(styles.Colors["bronze"])).
			Padding(0, 1)

	// FIXME: Hon pls help
	errorStatusMessageStyle = lipgloss.NewStyle().
				Foreground(lipgloss.AdaptiveColor{Dark: "#ff0000"}).
				Render

	selectedSourceItemStyle = lipgloss.NewStyle().
				Border(lipgloss.NormalBorder(), false, false, false, true).
				BorderForeground(lipgloss.AdaptiveColor{Dark: styles.Colors["sprout"], Light: styles.Colors["bronze"]}).
				Foreground(lipgloss.AdaptiveColor{Dark: styles.Colors["sprout"], Light: styles.Colors["fern"]}).
				Padding(0, 0, 0, 1)

	selectedDescription = selectedSourceItemStyle.Copy().
				Foreground(lipgloss.AdaptiveColor{Dark: styles.Colors["sprout"], Light: styles.Colors["sprout"]})
)

type listKeyMap struct {
	toggleHelpMenu key.Binding
}

type (
	SourceSelect struct {
		common.Common
		sourcesList  list.Model
		keys         *listKeyMap
		delegateKeys *delegateKeyMap
		selector     *selector.Selector
	}
	sourceSelectMsg struct {
		selection string
		cmd       *kingpin.CmdModel
	}
)

func New(c common.Common) *SourceSelect {
	var (
		delegateKeys = newDelegateKeyMap()
		listKeys     = &listKeyMap{
			toggleHelpMenu: key.NewBinding(
				key.WithKeys("H"),
				key.WithHelp("H", "toggle help"),
			),
		}
	)

	// Make list of SourceItems.
	SourceItems := []list.Item{
		// Open source sources.
		SourceItem{"Git", "Scan git repositories.", nil},
		SourceItem{"GitHub", "Scan GitHub repositories and/or organizations.", nil},
		SourceItem{"GitLab", "Scan GitLab repositories.", nil},
		SourceItem{"Filesystem", "Scan your filesystem by selecting what directories to scan.", nil},
		SourceItem{"AWS S3", "Scan Amazon S3 buckets.", nil},
		SourceItem{"CircleCI", "Scan CircleCI, a CI/CD platform.", nil},
		SourceItem{"Syslog", "Scan syslog, event data logs.", nil},
		// Enterprise sources.
		SourceItem{"Artifactory", "Scan JFrog Artifactory packages.", nil},
		SourceItem{"BitBucket", "Scan Atlassian's Git-based source code repository hosting service.", nil},
		SourceItem{"Buildkite", "Scan Buildkite, a CI/CD platform.", nil},
		SourceItem{"Confluence", "Scan Atlassian's web-based wiki and knowledge base.", nil},
		SourceItem{"Gerrit", "Scan Gerrit, a code collaboration tool", nil},
		SourceItem{"Jenkins ", "Scan Jenkins, a CI/CD platform.", nil},
		SourceItem{"Jira", "Scan Atlassian's issue & project tracking software.", nil},
		SourceItem{"Slack", "Scan Slack, a messaging and communication platform.", nil},
		SourceItem{"Microsoft Teams", "Scan Microsoft Teams, a messaging and communication platform.", nil},
	}

	// Setup list
	delegate := newSourceItemDelegate(delegateKeys)
	delegate.Styles.SelectedTitle = selectedSourceItemStyle
	delegate.Styles.SelectedDesc = selectedDescription

	sourcesList := list.New(SourceItems, delegate, 0, 0)
	sourcesList.Title = "Sources"
	sourcesList.Styles.Title = titleStyle
	sourcesList.StatusMessageLifetime = 10 * time.Second

	sourcesList.AdditionalFullHelpKeys = func() []key.Binding {
		return []key.Binding{
			listKeys.toggleHelpMenu,
		}
	}

	sourcesList.SetShowStatusBar(false)
	sel := selector.New(c, []selector.IdentifiableItem{}, delegate)

	return &SourceSelect{
		Common:       c,
		sourcesList:  sourcesList,
		keys:         listKeys,
		delegateKeys: delegateKeys,
		selector:     sel,
	}
}

func (m *SourceSelect) Init() tea.Cmd {
	return nil
}

func (m *SourceSelect) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		h, v := styles.AppStyle.GetFrameSize()
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

	if m.selector != nil {
		sel, cmd := m.selector.Update(msg)
		m.selector = sel.(*selector.Selector)
		cmds = append(cmds, cmd)
	}

	return m, tea.Batch(cmds...)
}

func (m *SourceSelect) View() string {
	return styles.AppStyle.Render(m.sourcesList.View())
}

func (m *SourceSelect) ShortHelp() []key.Binding {
	// TODO: actually return something
	return nil
}

func (m *SourceSelect) FullHelp() [][]key.Binding {
	// TODO: actually return something
	return nil
}

func newSourceItemDelegate(keys *delegateKeyMap) list.DefaultDelegate {
	d := list.NewDefaultDelegate()

	d.UpdateFunc = func(msg tea.Msg, m *list.Model) tea.Cmd {
		selectedSourceItem, ok := m.SelectedItem().(SourceItem)
		if !ok {
			return nil
		}

		if msg, ok := msg.(tea.KeyMsg); ok && key.Matches(msg, keys.choose) {
			if selectedSourceItem.isEnterprise() {
				return m.NewStatusMessage(errorStatusMessageStyle(
					"That's an enterprise only source. Learn more at trufflesecurity.com",
				))
			}

			return func() tea.Msg {
				return selector.SelectMsg{IdentifiableItem: selectedSourceItem}
			}
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
