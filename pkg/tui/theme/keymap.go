package theme

import "github.com/charmbracelet/bubbles/key"

// KeyMap is the trimmed replacement for pkg/tui/keymap.KeyMap.
//
// Only bindings actually observed in the TUI live here.
type KeyMap struct {
	// Quit closes the TUI at any depth via ctrl+c.
	Quit key.Binding
	// CmdQuit closes the TUI from a root page via `q`.
	CmdQuit key.Binding
	// Back pops the current page; exits if the stack is empty.
	Back key.Binding
	// Select activates the focused item (enter).
	Select key.Binding
	// Section moves between sections / tabs.
	Section key.Binding
	// UpDown navigates vertically within a list / form.
	UpDown key.Binding
	// LeftRight navigates horizontally (tabs, radio groups).
	LeftRight key.Binding
}

// DefaultKeyMap returns the default KeyMap.
func DefaultKeyMap() *KeyMap {
	km := new(KeyMap)

	km.Quit = key.NewBinding(
		key.WithKeys("ctrl+c"),
		key.WithHelp("ctrl+c", "quit"),
	)

	km.CmdQuit = key.NewBinding(
		key.WithKeys("q", "ctrl+c"),
		key.WithHelp("q", "quit"),
	)

	km.Back = key.NewBinding(
		key.WithKeys("esc"),
		key.WithHelp("esc", "back"),
	)

	km.Select = key.NewBinding(
		key.WithKeys("enter"),
		key.WithHelp("enter", "select"),
	)

	km.Section = key.NewBinding(
		key.WithKeys("tab", "shift+tab"),
		key.WithHelp("tab", "section"),
	)

	km.UpDown = key.NewBinding(
		key.WithKeys("up", "down", "k", "j"),
		key.WithHelp("↑↓", "navigate"),
	)

	km.LeftRight = key.NewBinding(
		key.WithKeys("left", "right", "h", "l"),
		key.WithHelp("←→", "navigate"),
	)

	return km
}
