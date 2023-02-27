package keymap

import "github.com/charmbracelet/bubbles/key"

// KeyMap is a map of key bindings for the UI.
type KeyMap struct {
	Quit      key.Binding
	Up        key.Binding
	Down      key.Binding
	UpDown    key.Binding
	LeftRight key.Binding
	Arrows    key.Binding
	Select    key.Binding
	Section   key.Binding
	Back      key.Binding
	PrevPage  key.Binding
	NextPage  key.Binding
	Help      key.Binding

	SelectItem key.Binding
	BackItem   key.Binding

	Copy key.Binding
}

// DefaultKeyMap returns the default key map.
func DefaultKeyMap() *KeyMap {
	km := new(KeyMap)

	km.Quit = key.NewBinding(
		key.WithKeys(
			"q",
			"ctrl+c",
		),
		key.WithHelp(
			"q",
			"quit",
		),
	)

	km.Up = key.NewBinding(
		key.WithKeys(
			"up",
			"k",
		),
		key.WithHelp(
			"↑",
			"up",
		),
	)

	km.Down = key.NewBinding(
		key.WithKeys(
			"down",
			"j",
		),
		key.WithHelp(
			"↓",
			"down",
		),
	)

	km.UpDown = key.NewBinding(
		key.WithKeys(
			"up",
			"down",
			"k",
			"j",
		),
		key.WithHelp(
			"↑↓",
			"navigate",
		),
	)

	km.LeftRight = key.NewBinding(
		key.WithKeys(
			"left",
			"h",
			"right",
			"l",
		),
		key.WithHelp(
			"←→",
			"navigate",
		),
	)

	km.Arrows = key.NewBinding(
		key.WithKeys(
			"up",
			"right",
			"down",
			"left",
			"k",
			"j",
			"h",
			"l",
		),
		key.WithHelp(
			"↑←↓→",
			"navigate",
		),
	)

	km.Select = key.NewBinding(
		key.WithKeys(
			"enter",
		),
		key.WithHelp(
			"enter",
			"select",
		),
	)

	km.Section = key.NewBinding(
		key.WithKeys(
			"tab",
			"shift+tab",
		),
		key.WithHelp(
			"tab",
			"section",
		),
	)

	km.Back = key.NewBinding(
		key.WithKeys(
			"esc",
		),
		key.WithHelp(
			"esc",
			"back",
		),
	)

	km.PrevPage = key.NewBinding(
		key.WithKeys(
			"pgup",
			"b",
			"u",
		),
		key.WithHelp(
			"pgup",
			"prev page",
		),
	)

	km.NextPage = key.NewBinding(
		key.WithKeys(
			"pgdown",
			"f",
			"d",
		),
		key.WithHelp(
			"pgdn",
			"next page",
		),
	)

	km.Help = key.NewBinding(
		key.WithKeys(
			"?",
		),
		key.WithHelp(
			"?",
			"toggle help",
		),
	)

	km.SelectItem = key.NewBinding(
		key.WithKeys(
			"l",
			"right",
		),
		key.WithHelp(
			"→",
			"select",
		),
	)

	km.BackItem = key.NewBinding(
		key.WithKeys(
			"h",
			"left",
			"backspace",
		),
		key.WithHelp(
			"←",
			"back",
		),
	)

	km.Copy = key.NewBinding(
		key.WithKeys(
			"c",
			"ctrl+c",
		),
		key.WithHelp(
			"c",
			"copy text",
		),
	)

	return km
}
