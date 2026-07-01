// Package app hosts the TUI router: a single model that owns a navigation
// stack of Pages and centralizes chrome, resize and global keys.
//
// The old pkg/tui.TUI god-model is replaced by app.Model. Pages no longer
// know about each other — they emit navigation messages (see messages.go) and
// the router takes care of pushing, popping, and handing off to the parent
// process.
package app

import (
	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
)

// PageID is the stable identifier used to register and look up pages.
type PageID string

// Well-known page IDs. Each page package exports its own ID constant as well;
// these are re-declared here so the router can reference them without
// importing every page package.
const (
	PageWizard         PageID = "wizard"
	PageSourcePicker   PageID = "source-picker"
	PageSourceConfig   PageID = "source-config"
	PageAnalyzerPicker PageID = "analyzer-picker"
	PageAnalyzerForm   PageID = "analyzer-form"
	PageLinkCard       PageID = "link-card"
)

// Page is the uniform contract every TUI page implements.
//
// The interface intentionally omits bubbles/help.KeyMap — pages expose only a
// short key binding list and the router renders the help line itself.
type Page interface {
	ID() PageID
	Init() tea.Cmd
	Update(tea.Msg) (Page, tea.Cmd)
	View() string
	// SetSize receives the content rectangle computed by the router, i.e.
	// the terminal size minus any chrome the router owns.
	SetSize(width, height int)
	// Help returns the short help bindings to display at the bottom of the
	// screen. nil is valid and means "no page-specific help".
	Help() []key.Binding
	// AllowQKey returns true if the `q` key should quit the app while this
	// page is the only entry on the stack. Text-entry pages should return
	// false so users can type the letter q.
	AllowQKey() bool
}

// Factory lazily constructs a page given optional navigation data.
//
// Pages are registered on the Model at construction time; the router calls
// the factory on every PushMsg so that re-entering a page gets a fresh
// instance rather than stale state from the previous visit.
type Factory func(data any) Page
