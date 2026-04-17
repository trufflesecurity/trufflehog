package app

import (
	"fmt"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	zone "github.com/lrstanley/bubblezone"

	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/theme"
)

// Minimum terminal size below which the router refuses to render any page.
const (
	minWidth  = 40
	minHeight = 10
)

// Model is the TUI router. It owns the navigation stack, chrome, global keys
// and the parent-process handoff. Pages know nothing about each other and
// only communicate through the navigation messages in messages.go.
type Model struct {
	styles    *theme.Styles
	keymap    *theme.KeyMap
	zone      *zone.Manager
	factories map[PageID]Factory
	stack     []Page
	width     int
	height    int

	// Deliverables passed back to pkg/tui.Run once the program exits.
	args         []string
	analyzerType string
	analyzerInfo analyzer.SecretInfo

	// initial page + data, resolved on first Update after WindowSizeMsg so
	// pages are created with a valid size from the start.
	initialID   PageID
	initialData any
	initialized bool
}

// New constructs a Model with default styles, keymap and zone manager. The
// caller is responsible for registering page factories with Register before
// calling Run, and for seeding the initial page with SetInitialPage.
func New() *Model {
	return &Model{
		styles:    theme.DefaultStyles(),
		keymap:    theme.DefaultKeyMap(),
		zone:      zone.New(),
		factories: make(map[PageID]Factory),
	}
}

// Register associates a PageID with a factory. Calling Register twice with
// the same ID panics; pages are expected to be registered once at startup.
func (m *Model) Register(id PageID, f Factory) {
	if _, ok := m.factories[id]; ok {
		panic(fmt.Sprintf("app: duplicate page factory for %q", id))
	}
	m.factories[id] = f
}

// SetInitialPage seeds the page the router should push on the first tick.
// The page is not constructed until the first tea.WindowSizeMsg so it sees a
// valid size from Init.
func (m *Model) SetInitialPage(id PageID, data any) {
	m.initialID = id
	m.initialData = data
}

// Styles returns the shared style sheet. Pages use this via the constructor
// dependency injected by their Factory.
func (m *Model) Styles() *theme.Styles { return m.styles }

// Keymap returns the shared keymap.
func (m *Model) Keymap() *theme.KeyMap { return m.keymap }

// Zone returns the shared bubblezone manager.
func (m *Model) Zone() *zone.Manager { return m.zone }

// Args is the arg vector to hand to kingpin on re-exec. nil means "user
// quit".
func (m *Model) Args() []string { return m.args }

// AnalyzerType is the lowercased analyzer name if the user completed an
// analyzer flow, empty string otherwise.
func (m *Model) AnalyzerType() string { return m.analyzerType }

// AnalyzerInfo carries the analyzer form submission, only valid when
// AnalyzerType() is non-empty.
func (m *Model) AnalyzerInfo() analyzer.SecretInfo { return m.analyzerInfo }

// Init implements tea.Model.
func (m *Model) Init() tea.Cmd { return nil }

func (m *Model) active() Page {
	if len(m.stack) == 0 {
		return nil
	}
	return m.stack[len(m.stack)-1]
}

func (m *Model) contentSize() (int, int) {
	// Router-owned chrome is the App style's frame size. The content
	// rectangle is whatever's left.
	hFrame, vFrame := m.styles.App.GetFrameSize()
	w := m.width - hFrame
	h := m.height - vFrame
	if w < 0 {
		w = 0
	}
	if h < 0 {
		h = 0
	}
	return w, h
}

func (m *Model) resizeActive() tea.Cmd {
	p := m.active()
	if p == nil {
		return nil
	}
	w, h := m.contentSize()
	p.SetSize(w, h)
	resize := ResizeMsg{Width: w, Height: h}
	_, cmd := p.Update(resize)
	return cmd
}

func (m *Model) push(id PageID, data any) tea.Cmd {
	f, ok := m.factories[id]
	if !ok {
		panic(fmt.Sprintf("app: no factory registered for page %q", id))
	}
	page := f(data)
	m.stack = append(m.stack, page)
	initCmd := page.Init()
	resizeCmd := m.resizeActive()
	return tea.Batch(initCmd, resizeCmd)
}

func (m *Model) pop() tea.Cmd {
	if len(m.stack) == 0 {
		return tea.Quit
	}
	m.stack = m.stack[:len(m.stack)-1]
	if len(m.stack) == 0 {
		return tea.Quit
	}
	return m.resizeActive()
}

func (m *Model) replace(id PageID, data any) tea.Cmd {
	if len(m.stack) > 0 {
		m.stack = m.stack[:len(m.stack)-1]
	}
	return m.push(id, data)
}

// Update implements tea.Model.
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		if !m.initialized {
			m.initialized = true
			if m.initialID == "" {
				return m, tea.Quit
			}
			return m, m.push(m.initialID, m.initialData)
		}
		return m, m.resizeActive()

	case tea.KeyMsg:
		if cmd := m.handleGlobalKey(msg); cmd != nil {
			return m, cmd
		}

	case PushMsg:
		return m, m.push(msg.ID, msg.Data)

	case PopMsg:
		return m, m.pop()

	case ReplaceMsg:
		return m, m.replace(msg.ID, msg.Data)

	case ExitMsg:
		m.args = msg.Args
		return m, tea.Quit

	case RunAnalyzerMsg:
		m.analyzerType = msg.Type
		m.analyzerInfo = msg.Info
		return m, tea.Quit
	}

	// Forward everything else to the active page.
	if p := m.active(); p != nil {
		next, cmd := p.Update(msg)
		m.stack[len(m.stack)-1] = next
		return m, cmd
	}
	return m, nil
}

func (m *Model) handleGlobalKey(msg tea.KeyMsg) tea.Cmd {
	switch {
	case key.Matches(msg, m.keymap.Quit):
		m.args = nil
		return tea.Quit
	case key.Matches(msg, m.keymap.CmdQuit):
		p := m.active()
		if p != nil && len(m.stack) == 1 && p.AllowQKey() {
			m.args = nil
			return tea.Quit
		}
	case key.Matches(msg, m.keymap.Back):
		if len(m.stack) <= 1 {
			m.args = nil
			return tea.Quit
		}
		return m.pop()
	}
	return nil
}

// View implements tea.Model.
func (m *Model) View() string {
	if m.width < minWidth || m.height < minHeight {
		return m.styles.App.Render(fmt.Sprintf(
			"Terminal too small — need at least %d×%d, got %d×%d",
			minWidth, minHeight, m.width, m.height,
		))
	}
	p := m.active()
	if p == nil {
		return ""
	}
	return m.zone.Scan(m.styles.App.Render(p.View()))
}
