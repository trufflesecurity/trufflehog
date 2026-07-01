package theme

import (
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/lipgloss"
)

// ListDelegate returns a bubbles/list DefaultDelegate styled with the
// TruffleHog palette: bronze for selected items and the hint smoke for
// descriptions. The library default is a pink/purple that clashes with the
// rest of the UI.
func ListDelegate() list.DefaultDelegate {
	d := list.NewDefaultDelegate()

	d.Styles.NormalTitle = lipgloss.NewStyle().
		Padding(0, 0, 0, 2)

	d.Styles.NormalDesc = lipgloss.NewStyle().
		Foreground(ColorHint).
		Padding(0, 0, 0, 2)

	d.Styles.SelectedTitle = lipgloss.NewStyle().
		Border(lipgloss.NormalBorder(), false, false, false, true).
		BorderForeground(ColorSelectBG).
		Foreground(ColorSelectBG).
		Bold(true).
		Padding(0, 0, 0, 1)

	d.Styles.SelectedDesc = lipgloss.NewStyle().
		Border(lipgloss.NormalBorder(), false, false, false, true).
		BorderForeground(ColorSelectBG).
		Foreground(ColorSelectBG).
		Padding(0, 0, 0, 1)

	d.Styles.DimmedTitle = lipgloss.NewStyle().
		Foreground(ColorMuted).
		Padding(0, 0, 0, 2)

	d.Styles.DimmedDesc = lipgloss.NewStyle().
		Foreground(ColorMuted).
		Padding(0, 0, 0, 2)

	d.Styles.FilterMatch = lipgloss.NewStyle().
		Foreground(ColorPrimary).
		Underline(true)

	return d
}

// ApplyListStyles overrides the bubbles/list chrome (title, filter prompt,
// pagination, help) with brand colors. Pages own their list.Model and call
// this after construction.
func ApplyListStyles(l *list.Model, s *Styles) {
	l.Styles.Title = s.Title
	l.Styles.FilterPrompt = lipgloss.NewStyle().Foreground(ColorSelectBG)
	l.Styles.FilterCursor = lipgloss.NewStyle().Foreground(ColorSelectBG)
	l.Styles.DefaultFilterCharacterMatch = lipgloss.NewStyle().
		Foreground(ColorPrimary).
		Underline(true)
	l.Styles.NoItems = lipgloss.NewStyle().Foreground(ColorHint)
	l.Styles.HelpStyle = lipgloss.NewStyle().Foreground(ColorHint).Padding(1, 0, 0, 2)
	l.Styles.PaginationStyle = lipgloss.NewStyle().Foreground(ColorHint).PaddingLeft(2)
	l.Styles.ActivePaginationDot = lipgloss.NewStyle().Foreground(ColorSelectBG).SetString("•")
	l.Styles.InactivePaginationDot = lipgloss.NewStyle().Foreground(ColorHint).SetString("•")
}
