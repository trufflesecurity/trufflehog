// Package wizard is the root landing page: a list of top-level actions.
package wizard

import (
	"strings"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/app"
	linkcard "github.com/trufflesecurity/trufflehog/v3/pkg/tui/pages/link-card"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/theme"
)

// ID is the stable page id.
const ID = app.PageWizard

// action is a wizard menu entry. It is not exported; the page emits the
// appropriate navigation message when one is chosen.
type action int

const (
	actionScan action = iota
	actionAnalyze
	actionHelp
	actionOSS
	actionEnterprise
	actionQuit
)

func (a action) label() string {
	return []string{
		"Scan a source using wizard",
		"Analyze a secret's permissions",
		"View help docs",
		"View open-source project",
		"Inquire about TruffleHog Enterprise",
		"Quit",
	}[a]
}

var allActions = []action{
	actionScan, actionAnalyze, actionHelp,
	actionOSS, actionEnterprise, actionQuit,
}

// Page is the tea.Model implementation for the root wizard.
type Page struct {
	styles *theme.Styles
	keymap *theme.KeyMap
	cursor int
}

// New constructs a wizard page.
func New(styles *theme.Styles, keymap *theme.KeyMap, _ any) *Page {
	return &Page{styles: styles, keymap: keymap}
}

func (p *Page) ID() app.PageID { return ID }

func (p *Page) Init() tea.Cmd { return nil }

func (p *Page) Update(msg tea.Msg) (app.Page, tea.Cmd) {
	km, ok := msg.(tea.KeyMsg)
	if !ok {
		return p, nil
	}
	switch {
	case key.Matches(km, p.keymap.UpDown):
		if km.String() == "up" || km.String() == "k" {
			if p.cursor > 0 {
				p.cursor--
			}
		} else {
			if p.cursor < len(allActions)-1 {
				p.cursor++
			}
		}
	case key.Matches(km, p.keymap.Select):
		return p, p.activate()
	}
	return p, nil
}

func (p *Page) activate() tea.Cmd {
	switch allActions[p.cursor] {
	case actionScan:
		return pushCmd(app.PageSourcePicker, nil)
	case actionAnalyze:
		return pushCmd(app.PageAnalyzerPicker, nil)
	case actionHelp:
		return exitCmd([]string{"--help"})
	case actionOSS:
		return pushCmd(app.PageLinkCard, ossLinkData())
	case actionEnterprise:
		return pushCmd(app.PageLinkCard, enterpriseLinkData())
	case actionQuit:
		return exitCmd(nil)
	}
	return nil
}

func (p *Page) View() string {
	var b strings.Builder
	b.WriteString("What do you want to do?\n\n")
	for i, a := range allActions {
		if i == p.cursor {
			b.WriteString(p.styles.Primary.Render(" (•) " + a.label()))
		} else {
			b.WriteString(" ( ) " + a.label())
		}
		b.WriteString("\n")
	}
	return b.String()
}

func (p *Page) SetSize(width, height int) {}

func (p *Page) Help() []key.Binding {
	return []key.Binding{p.keymap.UpDown, p.keymap.Select}
}

func (p *Page) AllowQKey() bool { return true }

func pushCmd(id app.PageID, data any) tea.Cmd {
	return func() tea.Msg { return app.PushMsg{ID: id, Data: data} }
}

func exitCmd(args []string) tea.Cmd {
	return func() tea.Msg { return app.ExitMsg{Args: args} }
}

func ossLinkData() any {
	return linkcard.Data{
		Title: "View our open-source project on GitHub",
		URL:   "https://github.com/trufflesecurity/trufflehog",
	}
}

func enterpriseLinkData() any {
	return linkcard.Data{
		Title: "Interested in TruffleHog enterprise?",
		URL:   "https://trufflesecurity.com/contact",
	}
}
