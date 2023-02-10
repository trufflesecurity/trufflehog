package footer

import (
	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/soft-serve/ui/common"
)

// ToggleFooterMsg is a message sent to show/hide the footer.
type ToggleFooterMsg struct{}

// Footer is a Bubble Tea model that displays help and other info.
type Footer struct {
	common common.Common
	help   help.Model
	keymap help.KeyMap
}

// New creates a new Footer.
func New(c common.Common, keymap help.KeyMap) *Footer {
	h := help.New()
	h.Styles.ShortKey = c.Styles.HelpKey
	h.Styles.ShortDesc = c.Styles.HelpValue
	h.Styles.FullKey = c.Styles.HelpKey
	h.Styles.FullDesc = c.Styles.HelpValue
	f := &Footer{
		common: c,
		help:   h,
		keymap: keymap,
	}
	f.SetSize(c.Width, c.Height)
	return f
}

// SetSize implements common.Component.
func (f *Footer) SetSize(width, height int) {
	f.common.SetSize(width, height)
	f.help.Width = width -
		f.common.Styles.Footer.GetHorizontalFrameSize()
}

// Init implements tea.Model.
func (f *Footer) Init() tea.Cmd {
	return nil
}

// Update implements tea.Model.
func (f *Footer) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	return f, nil
}

// View implements tea.Model.
func (f *Footer) View() string {
	if f.keymap == nil {
		return ""
	}
	s := f.common.Styles.Footer.Copy().
		Width(f.common.Width)
	helpView := f.help.View(f.keymap)
	return f.common.Zone.Mark(
		"footer",
		s.Render(helpView),
	)
}

// ShortHelp returns the short help key bindings.
func (f *Footer) ShortHelp() []key.Binding {
	return f.keymap.ShortHelp()
}

// FullHelp returns the full help key bindings.
func (f *Footer) FullHelp() [][]key.Binding {
	return f.keymap.FullHelp()
}

// ShowAll returns whether the full help is shown.
func (f *Footer) ShowAll() bool {
	return f.help.ShowAll
}

// SetShowAll sets whether the full help is shown.
func (f *Footer) SetShowAll(show bool) {
	f.help.ShowAll = show
}

// Height returns the height of the footer.
func (f *Footer) Height() int {
	return lipgloss.Height(f.View())
}

// ToggleFooterCmd sends a ToggleFooterMsg to show/hide the help footer.
func ToggleFooterCmd() tea.Msg {
	return ToggleFooterMsg{}
}
