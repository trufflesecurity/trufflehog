package styles

import (
	"github.com/charmbracelet/lipgloss"
)

// DEPRECATED: package styles is retained only while the legacy pages migrate
// to pkg/tui/theme. New code should reach for pkg/tui/theme instead.

// Colors is the named palette kept intact so existing pages that index into
// it don't break mid-migration.
var Colors = map[string]string{
	"softblack": "#1e1e1e",
	"charcoal":  "#252525",
	"stone":     "#5a5a5a",
	"smoke":     "#999999",
	"sand":      "#e1deda",
	"cloud":     "#f4efe9",
	"offwhite":  "#faf8f7",
	"fern":      "#38645a",
	"sprout":    "#5bb381",
	"gold":      "#ae8c57",
	"bronze":    "#89553d",
	"coral":     "#c15750",
	"violet":    "#6b5b9a",
}

var (
	BoldTextStyle = lipgloss.NewStyle().Bold(true)

	PrimaryTextStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("28"))

	HintTextStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))

	CodeTextStyle = lipgloss.NewStyle().Background(lipgloss.Color("130")).Foreground(lipgloss.Color("15"))
)

var AppStyle = lipgloss.NewStyle().Padding(1, 2)

// Styles defines styles for the UI. Only fields that are actually rendered
// somewhere in the TUI are kept here; the Soft Serve-era fields (Repo, Log,
// Tree, StatusBar*, Ref, Spinner, Error*, TopLevel*, Branch, ServerName,
// AboutNoReadme, CodeNoContent, Footer, HelpKey, HelpValue, HelpDivider,
// URLStyle, MenuLastUpdate, Tabs, ActiveBorderColor, InactiveBorderColor)
// have been removed.
type Styles struct {
	App lipgloss.Style

	MenuItem lipgloss.Style

	RepoSelector struct {
		Normal struct {
			Base    lipgloss.Style
			Title   lipgloss.Style
			Desc    lipgloss.Style
			Command lipgloss.Style
			Updated lipgloss.Style
		}
		Active struct {
			Base    lipgloss.Style
			Title   lipgloss.Style
			Desc    lipgloss.Style
			Command lipgloss.Style
			Updated lipgloss.Style
		}
	}

	TabInactive  lipgloss.Style
	TabActive    lipgloss.Style
	TabSeparator lipgloss.Style
}

// DefaultStyles returns default styles for the UI.
func DefaultStyles() *Styles {
	s := new(Styles)

	s.App = lipgloss.NewStyle().
		Margin(1, 2)

	s.RepoSelector.Normal.Base = lipgloss.NewStyle().
		PaddingLeft(1).
		Border(lipgloss.Border{Left: " "}, false, false, false, true).
		Height(3)

	s.RepoSelector.Normal.Title = lipgloss.NewStyle().Bold(true)

	s.RepoSelector.Normal.Desc = lipgloss.NewStyle().
		Foreground(lipgloss.Color("243"))

	s.RepoSelector.Normal.Command = lipgloss.NewStyle().
		Foreground(lipgloss.Color("132"))

	s.RepoSelector.Normal.Updated = lipgloss.NewStyle().
		Foreground(lipgloss.Color("243"))

	s.RepoSelector.Active.Base = s.RepoSelector.Normal.Base.
		BorderStyle(lipgloss.Border{Left: "┃"}).
		BorderForeground(lipgloss.Color("176"))

	s.RepoSelector.Active.Title = s.RepoSelector.Normal.Title.
		Foreground(lipgloss.Color("212"))

	s.RepoSelector.Active.Desc = s.RepoSelector.Normal.Desc.
		Foreground(lipgloss.Color("246"))

	s.RepoSelector.Active.Updated = s.RepoSelector.Normal.Updated.
		Foreground(lipgloss.Color("212"))

	s.RepoSelector.Active.Command = s.RepoSelector.Normal.Command.
		Foreground(lipgloss.Color("204"))

	s.MenuItem = lipgloss.NewStyle().
		PaddingLeft(1).
		Border(lipgloss.Border{
			Left: " ",
		}, false, false, false, true).
		Height(3)

	s.TabInactive = lipgloss.NewStyle()

	s.TabActive = lipgloss.NewStyle().
		Underline(true).
		Foreground(lipgloss.Color("36"))

	s.TabSeparator = lipgloss.NewStyle().
		SetString("│").
		Padding(0, 1).
		Foreground(lipgloss.Color("238"))

	return s
}
