package tui

import (
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	zone "github.com/lrstanley/bubblezone"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/components/selector"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/keymap"
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
)

type sessionState int

const (
	startState sessionState = iota
	errorState
	loadedState
)

// TUI is the main TUI model.
type TUI struct {
	common     common.Common
	pages      []common.Component
	activePage page
	state      sessionState
	args       []string
}

// New returns a new TUI model.
func New(c common.Common) *TUI {
	ui := &TUI{
		common:     c,
		pages:      make([]common.Component, 5),
		activePage: wizardIntroPage,
		state:      startState,
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
	ui.SetSize(ui.common.Width, ui.common.Height)
	cmds := make([]tea.Cmd, 0)
	cmds = append(cmds,
		ui.pages[wizardIntroPage].Init(),
		ui.pages[sourceSelectPage].Init(),
		ui.pages[sourceConfigurePage].Init(),
		ui.pages[viewOSSProjectPage].Init(),
		ui.pages[contactEnterprisePage].Init(),
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
			case key.Matches(msg, ui.common.KeyMap.CmdQuit) && ui.activePage != sourceConfigurePage:
				return ui, tea.Quit
			case key.Matches(msg, ui.common.KeyMap.Quit):
				return ui, tea.Quit
			case ui.activePage > 0 && key.Matches(msg, ui.common.KeyMap.Back):
				ui.activePage -= 1
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
				cmds = append(cmds, tea.Quit)
			case wizard_intro.ViewOSSProject:
				ui.activePage = viewOSSProjectPage
			case wizard_intro.ViewHelpDocs:
				ui.args = []string{"--help"}

				return ui, tea.Batch(nil, tea.Quit)
			case wizard_intro.EnterpriseInquire:
				ui.activePage = contactEnterprisePage
			case wizard_intro.ScanSourceWithWizard:
				ui.activePage = sourceSelectPage
			}
		case source_select.SourceItem:
			ui.activePage = sourceConfigurePage
			cmds = append(cmds, func() tea.Msg {
				return source_configure.SetSourceMsg{Source: item.ID()}
			})
		}
	case source_configure.SetArgsMsg:
		ui.args = strings.Split(string(msg), " ")[1:]
		return ui, tea.Quit
	}

	if ui.state == loadedState {
		m, cmd := ui.pages[ui.activePage].Update(msg)
		ui.pages[ui.activePage] = m.(common.Component)
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
		view = ui.pages[ui.activePage].View()
	default:
		view = "Unknown state :/ this is a bug!"
	}
	return ui.common.Zone.Scan(
		ui.common.Styles.App.Render(view),
	)
}

func Run() []string {
	c := common.Common{
		Copy:   nil,
		Styles: styles.DefaultStyles(),
		KeyMap: keymap.DefaultKeyMap(),
		Width:  0,
		Height: 0,
		Zone:   zone.New(),
	}
	m := New(c)
	p := tea.NewProgram(m)
	// TODO: Print normal help message.
	if _, err := p.Run(); err != nil {
		fmt.Printf("Alas, there's been an error: %v", err)
		os.Exit(1)
	}
	return m.args
}
