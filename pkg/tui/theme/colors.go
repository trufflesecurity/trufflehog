// Package theme centralizes colors, styles and key bindings for the TUI.
//
// All UI code should source colors and styles from this package so that the
// visual language stays consistent across pages and the set of literal color
// codes in the tree is kept to zero.
package theme

import "github.com/charmbracelet/lipgloss"

// Named palette. These are the only colors the TUI is allowed to use; the
// names follow the TruffleHog marketing palette.
var (
	Softblack = lipgloss.Color("#1e1e1e")
	Charcoal  = lipgloss.Color("#252525")
	Stone     = lipgloss.Color("#5a5a5a")
	Smoke     = lipgloss.Color("#999999")
	Sand      = lipgloss.Color("#e1deda")
	Cloud     = lipgloss.Color("#f4efe9")
	Offwhite  = lipgloss.Color("#faf8f7")
	Fern      = lipgloss.Color("#38645a")
	Sprout    = lipgloss.Color("#5bb381")
	Gold      = lipgloss.Color("#ae8c57")
	Bronze    = lipgloss.Color("#89553d")
	Coral     = lipgloss.Color("#c15750")
	Violet    = lipgloss.Color("#6b5b9a")
)

// Semantic roles. Pages should reach for these rather than the named palette
// so that a palette change at the top of the file propagates everywhere.
var (
	ColorPrimary   = Sprout
	ColorAccent    = Bronze
	ColorHint      = Smoke
	ColorMuted     = Stone
	ColorError     = Coral
	ColorLink      = Violet
	ColorCodeBG    = Bronze
	ColorCodeFG    = Offwhite
	ColorSelectBG  = Bronze
	ColorSelectFG  = Offwhite
	ColorTabActive = Fern
)
