package tui

import (
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	zone "github.com/lrstanley/bubblezone"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/components/selector"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/keymap"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/pages/analyze_form"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/pages/analyze_keys"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/pages/contact_enterprise"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/pages/source_configure"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/pages/source_select"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/pages/view_oss"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/pages/wizard_intro"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/styles"
)

type page int

const (
	wizardIntroPage page = iota
	sourceSelectPage
	sourceConfigurePage
	viewOSSProjectPage
	contactEnterprisePage
	analyzeKeysPage
	analyzeFormPage
)

type sessionState int

const (
	startState sessionState = iota
	errorState
	loadedState
)

// TUI is the main TUI model.
type TUI struct {
	common      common.Common
	pages       []common.Component
	pageHistory []page
	state       sessionState
	args        []string

	// Analyzer specific values that are only set if running an analysis.
	analyzerType string
	analyzerInfo analyzer.SecretInfo
}

// New returns a new TUI model.
func New(c common.Common, args []string) *TUI {
	ui := &TUI{
		common:      c,
		pages:       make([]common.Component, 7),
		pageHistory: []page{wizardIntroPage},
		state:       startState,
		args:        args,
	}
	switch {
	case len(args) == 0:
		return ui
	case len(args) == 1 && args[0] == "analyze":
		ui.pageHistory = []page{wizardIntroPage, analyzeKeysPage}
	}
	return ui
}

// SetSize implements common.Component.
func (ui *TUI) SetSize(width, height int) {
	ui.common.SetSize(width, height)
	for _, p := range ui.pages {
		if p != nil {
			p.SetSize(width, height)
		}
	}
}

// Init implements tea.Model.
func (ui *TUI) Init() tea.Cmd {

	ui.pages[wizardIntroPage] = wizard_intro.New(ui.common)
	ui.pages[sourceSelectPage] = source_select.New(ui.common)
	ui.pages[sourceConfigurePage] = source_configure.New(ui.common)
	ui.pages[viewOSSProjectPage] = view_oss.New(ui.common)
	ui.pages[contactEnterprisePage] = contact_enterprise.New(ui.common)
	ui.pages[analyzeKeysPage] = analyze_keys.New(ui.common)

	if len(ui.args) > 1 && ui.args[0] == "analyze" {
		analyzerArg := strings.ToLower(ui.args[1])
		ui.pages[analyzeFormPage] = analyze_form.New(ui.common, analyzerArg)
		ui.setActivePage(analyzeKeysPage)

		for _, analyzer := range analyzers.AvailableAnalyzers() {
			if strings.ToLower(analyzer) == analyzerArg {
				ui.setActivePage(analyzeFormPage)
			}
		}
	} else {
		ui.pages[analyzeFormPage] = analyze_form.New(ui.common, "this is a bug")
	}

	ui.SetSize(ui.common.Width, ui.common.Height)
	cmds := make([]tea.Cmd, 0)
	cmds = append(cmds,
		ui.pages[wizardIntroPage].Init(),
		ui.pages[sourceSelectPage].Init(),
		ui.pages[sourceConfigurePage].Init(),
		ui.pages[viewOSSProjectPage].Init(),
		ui.pages[contactEnterprisePage].Init(),
		ui.pages[analyzeKeysPage].Init(),
		ui.pages[analyzeFormPage].Init(),
	)
	ui.state = loadedState
	ui.SetSize(ui.common.Width, ui.common.Height)
	return tea.Batch(cmds...)
}

// Update implements tea.Model.
func (ui *TUI) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	cmds := make([]tea.Cmd, 0)
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		ui.SetSize(msg.Width, msg.Height)
		for i, p := range ui.pages {
			m, cmd := p.Update(msg)
			ui.pages[i] = m.(common.Component)
			if cmd != nil {
				cmds = append(cmds, cmd)
			}
		}
	case tea.KeyMsg, tea.MouseMsg:
		switch msg := msg.(type) {
		case tea.KeyMsg:
			switch {
			case key.Matches(msg, ui.common.KeyMap.Help):
			case key.Matches(msg, ui.common.KeyMap.CmdQuit) &&
				(ui.activePage() == wizardIntroPage || ui.activePage() == analyzeKeysPage || ui.activePage() == sourceSelectPage):

				ui.args = nil
				return ui, tea.Quit
			case key.Matches(msg, ui.common.KeyMap.Quit):
				ui.args = nil
				return ui, tea.Quit
			case key.Matches(msg, ui.common.KeyMap.Back):
				if ui.activePage() == wizardIntroPage {
					ui.args = nil
					return ui, tea.Quit
				}
				_ = ui.popHistory()
				return ui, nil
			}
		}
	case common.ErrorMsg:
		return ui, nil
	case selector.SelectMsg:
		switch item := msg.IdentifiableItem.(type) {
		case wizard_intro.Item:

			switch item {
			case wizard_intro.Quit:
				ui.args = nil
				cmds = append(cmds, tea.Quit)
			case wizard_intro.ViewOSSProject:
				ui.setActivePage(viewOSSProjectPage)
			case wizard_intro.ViewHelpDocs:
				ui.args = []string{"--help"}
				return ui, tea.Quit
			case wizard_intro.EnterpriseInquire:
				ui.setActivePage(contactEnterprisePage)
			case wizard_intro.ScanSourceWithWizard:
				ui.setActivePage(sourceSelectPage)
			case wizard_intro.AnalyzeSecret:
				ui.setActivePage(analyzeKeysPage)
			}
		case source_select.SourceItem:
			ui.setActivePage(sourceConfigurePage)
			cmds = append(cmds, func() tea.Msg {
				return source_configure.SetSourceMsg{Source: item.ID()}
			})
		case analyze_keys.KeyTypeItem:
			ui.setActivePage(analyzeFormPage)
			cmds = append(cmds, func() tea.Msg {
				return analyze_form.SetAnalyzerMsg(item.ID())
			})
		}
	case source_configure.SetArgsMsg:
		ui.args = strings.Split(string(msg), " ")[1:]
		return ui, tea.Quit
	case analyze_form.Submission:
		ui.analyzerType = msg.AnalyzerType
		ui.analyzerInfo = msg.AnalyzerInfo
		return ui, tea.Quit
	}

	if ui.state == loadedState {
		m, cmd := ui.pages[ui.activePage()].Update(msg)
		ui.pages[ui.activePage()] = m.(common.Component)
		if cmd != nil {
			cmds = append(cmds, cmd)
		}
	}

	// This fixes determining the height margin of the footer.
	// ui.SetSize(ui.common.Width, ui.common.Height)
	return ui, tea.Batch(cmds...)
}

// View implements tea.Model.
func (ui *TUI) View() string {
	var view string
	switch ui.state {
	case startState:
		view = "Loading..."
	case loadedState:
		view = ui.pages[ui.activePage()].View()
	default:
		view = "Unknown state :/ this is a bug!"
	}
	return ui.common.Zone.Scan(
		ui.common.Styles.App.Render(view),
	)
}

func Run(args []string) []string {
	c := common.Common{
		Copy:   nil,
		Styles: styles.DefaultStyles(),
		KeyMap: keymap.DefaultKeyMap(),
		Width:  0,
		Height: 0,
		Zone:   zone.New(),
	}
	m := New(c, args)
	p := tea.NewProgram(m)
	// TODO: Print normal help message.
	if _, err := p.Run(); err != nil {
		fmt.Printf("Alas, there's been an error: %v", err)
		os.Exit(1)
	}
	if m.analyzerType != "" {
		analyzer.Run(m.analyzerType, m.analyzerInfo)
		os.Exit(0)
	}
	return m.args
}

func (ui *TUI) activePage() page {
	if len(ui.pageHistory) == 0 {
		return wizardIntroPage
	}
	return ui.pageHistory[len(ui.pageHistory)-1]
}

func (ui *TUI) popHistory() page {
	if len(ui.pageHistory) == 0 {
		return wizardIntroPage
	}
	p := ui.activePage()
	ui.pageHistory = ui.pageHistory[:len(ui.pageHistory)-1]
	return p
}

func (ui *TUI) setActivePage(p page) {
	ui.pageHistory = append(ui.pageHistory, p)
}
