package theme

import "github.com/charmbracelet/lipgloss"

// Styles is the style sheet the TUI renders with. Only fields actually
// rendered somewhere live here; if you find yourself adding a field that
// isn't rendered on-screen, delete it instead.
type Styles struct {
	// App is applied once at the router level; every page view is rendered
	// inside its frame.
	App lipgloss.Style

	// Text roles.
	Title   lipgloss.Style
	Hint    lipgloss.Style
	Primary lipgloss.Style
	Bold    lipgloss.Style
	Code    lipgloss.Style
	Link    lipgloss.Style
	Error   lipgloss.Style

	// Menu / list items (wizard + source picker).
	MenuItem     lipgloss.Style
	SelectedItem lipgloss.Style

	// Tabs (source-config page).
	TabActive    lipgloss.Style
	TabInactive  lipgloss.Style
	TabSeparator lipgloss.Style
}

// DefaultStyles returns the default Styles.
func DefaultStyles() *Styles {
	s := new(Styles)

	s.App = lipgloss.NewStyle().Margin(1, 2)

	s.Title = lipgloss.NewStyle().
		Foreground(ColorAccent).
		Background(Offwhite).
		Bold(true).
		Padding(0, 1)

	s.Hint = lipgloss.NewStyle().Foreground(ColorHint)
	s.Primary = lipgloss.NewStyle().Foreground(ColorPrimary)
	s.Bold = lipgloss.NewStyle().Bold(true)

	s.Code = lipgloss.NewStyle().
		Background(ColorCodeBG).
		Foreground(ColorCodeFG)

	s.Link = lipgloss.NewStyle().
		Foreground(ColorLink).
		Underline(true)

	s.Error = lipgloss.NewStyle().Foreground(ColorError)

	s.MenuItem = lipgloss.NewStyle().
		PaddingLeft(1).
		Border(lipgloss.Border{Left: " "}, false, false, false, true).
		Height(3)

	s.SelectedItem = lipgloss.NewStyle().
		PaddingLeft(1).
		Border(lipgloss.Border{Left: "┃"}, false, false, false, true).
		BorderForeground(ColorAccent).
		Foreground(ColorAccent).
		Bold(true).
		Height(3)

	s.TabActive = lipgloss.NewStyle().
		Underline(true).
		Foreground(ColorTabActive)

	s.TabInactive = lipgloss.NewStyle()

	s.TabSeparator = lipgloss.NewStyle().
		SetString("│").
		Padding(0, 1).
		Foreground(Smoke)

	return s
}
