package source_configure

import (
	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/components/tabs"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/components/textinputs"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/sources"
)

type SetSourceMsg struct {
	Source string
}

type tab int

const (
	configTab tab = iota
	truffleConfigTab
	runTab
)

func (t tab) String() string {
	return []string{
		"1. Source Configuration",
		"2. TruffleHog Configuration",
		"3. Run",
	}[t]
}

type SourceConfigure struct {
	common.Common
	activeTab       tab
	tabs            *tabs.Tabs
	configTabSource string
	tabComponents   []common.Component
	sourceFields    sources.CmdModel
	truffleFields   sources.CmdModel
}

func (m SourceConfigure) Init() tea.Cmd {
	return m.tabs.Init()
}

func New(c common.Common) *SourceConfigure {
	conf := SourceConfigure{Common: c, truffleFields: GetTrufflehogConfiguration()}
	conf.tabs = tabs.New(c, []string{configTab.String(), truffleConfigTab.String(), runTab.String()})

	conf.tabComponents = []common.Component{
		configTab:        NewSourceComponent(c, &conf),
		truffleConfigTab: NewTrufflehogComponent(c, &conf),
		runTab:           NewRunComponent(c, &conf),
	}
	return &conf
}

func (m *SourceConfigure) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		for i := range m.tabComponents {
			model, cmd := m.tabComponents[i].Update(msg)
			m.tabComponents[i] = model.(common.Component)
			cmds = append(cmds, cmd)
		}

	case tabs.ActiveTabMsg:
		m.activeTab = tab(msg)
		t, cmd := m.tabs.Update(msg)
		m.tabs = t.(*tabs.Tabs)

		if cmd != nil {
			cmds = append(cmds, cmd)
		}
	case tabs.SelectTabMsg:
		m.activeTab = tab(msg)
		t, cmd := m.tabs.Update(msg)
		m.tabs = t.(*tabs.Tabs)

		if cmd != nil {
			cmds = append(cmds, cmd)
		}
	case tea.KeyMsg:
		t, cmd := m.tabs.Update(msg)
		m.tabs = t.(*tabs.Tabs)
		if cmd != nil {
			cmds = append(cmds, cmd)
		}
	case SetSourceMsg:
		m.configTabSource = msg.Source
		// TODO: Use actual messages or something?
		m.tabComponents[truffleConfigTab].(*TrufflehogComponent).SetForm(m.truffleFields)
		fields := sources.GetSourceFields(m.configTabSource)

		if fields != nil {
			m.sourceFields = fields
			m.tabComponents[configTab].(*SourceComponent).SetForm(fields)
		}

	case textinputs.SelectNextMsg, textinputs.SelectSkipMsg:
		if m.activeTab < runTab {
			m.activeTab++
		}
		t, cmd := m.tabs.Update(tabs.SelectTabMsg(int(m.activeTab)))
		m.tabs = t.(*tabs.Tabs)

		if cmd != nil {
			cmds = append(cmds, cmd)
		}
	}

	tab, cmd := m.tabComponents[m.activeTab].Update(msg)
	m.tabComponents[m.activeTab] = tab.(common.Component)
	if cmd != nil {
		cmds = append(cmds, cmd)
	}

	return m, tea.Batch(cmds...)
}

func (m *SourceConfigure) View() string {
	return lipgloss.JoinVertical(lipgloss.Top,
		m.tabs.View(),
		m.tabComponents[m.activeTab].View(),
	)
}

func (m *SourceConfigure) ShortHelp() []key.Binding {
	// TODO: actually return something
	return nil
}

func (m *SourceConfigure) FullHelp() [][]key.Binding {
	// TODO: actually return something
	return nil
}
