package styles

import (
	"github.com/charmbracelet/lipgloss"
)

// XXX: For now, this is in its own package so that it can be shared between
// different packages without incurring an illegal import cycle.

// Styles defines styles for the UI.
type Styles struct {
	ActiveBorderColor   lipgloss.Color
	InactiveBorderColor lipgloss.Color

	App                  lipgloss.Style
	ServerName           lipgloss.Style
	TopLevelNormalTab    lipgloss.Style
	TopLevelActiveTab    lipgloss.Style
	TopLevelActiveTabDot lipgloss.Style

	MenuItem       lipgloss.Style
	MenuLastUpdate lipgloss.Style

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

	Repo struct {
		Base       lipgloss.Style
		Title      lipgloss.Style
		Command    lipgloss.Style
		Body       lipgloss.Style
		Header     lipgloss.Style
		HeaderName lipgloss.Style
		HeaderDesc lipgloss.Style
	}

	Footer      lipgloss.Style
	Branch      lipgloss.Style
	HelpKey     lipgloss.Style
	HelpValue   lipgloss.Style
	HelpDivider lipgloss.Style
	URLStyle    lipgloss.Style

	Error      lipgloss.Style
	ErrorTitle lipgloss.Style
	ErrorBody  lipgloss.Style

	AboutNoReadme lipgloss.Style

	LogItem struct {
		Normal struct {
			Base    lipgloss.Style
			Hash    lipgloss.Style
			Title   lipgloss.Style
			Desc    lipgloss.Style
			Keyword lipgloss.Style
		}
		Active struct {
			Base    lipgloss.Style
			Hash    lipgloss.Style
			Title   lipgloss.Style
			Desc    lipgloss.Style
			Keyword lipgloss.Style
		}
	}

	Log struct {
		Commit         lipgloss.Style
		CommitHash     lipgloss.Style
		CommitAuthor   lipgloss.Style
		CommitDate     lipgloss.Style
		CommitBody     lipgloss.Style
		CommitStatsAdd lipgloss.Style
		CommitStatsDel lipgloss.Style
		Paginator      lipgloss.Style
	}

	Ref struct {
		Normal struct {
			Item    lipgloss.Style
			ItemTag lipgloss.Style
		}
		Active struct {
			Item    lipgloss.Style
			ItemTag lipgloss.Style
		}
		ItemSelector lipgloss.Style
		ItemBranch   lipgloss.Style
		Paginator    lipgloss.Style
	}

	Tree struct {
		Normal struct {
			FileName lipgloss.Style
			FileDir  lipgloss.Style
			FileMode lipgloss.Style
			FileSize lipgloss.Style
		}
		Active struct {
			FileName lipgloss.Style
			FileDir  lipgloss.Style
			FileMode lipgloss.Style
			FileSize lipgloss.Style
		}
		Selector    lipgloss.Style
		FileContent lipgloss.Style
		Paginator   lipgloss.Style
		NoItems     lipgloss.Style
	}

	Spinner lipgloss.Style

	CodeNoContent lipgloss.Style

	StatusBar       lipgloss.Style
	StatusBarKey    lipgloss.Style
	StatusBarValue  lipgloss.Style
	StatusBarInfo   lipgloss.Style
	StatusBarBranch lipgloss.Style
	StatusBarHelp   lipgloss.Style

	Tabs         lipgloss.Style
	TabInactive  lipgloss.Style
	TabActive    lipgloss.Style
	TabSeparator lipgloss.Style
}

// DefaultStyles returns default styles for the UI.
func DefaultStyles() *Styles {
	highlightColor := lipgloss.Color("210")
	highlightColorDim := lipgloss.Color("174")
	selectorColor := lipgloss.Color("167")
	hashColor := lipgloss.Color("185")

	s := new(Styles)

	s.ActiveBorderColor = lipgloss.Color("62")
	s.InactiveBorderColor = lipgloss.Color("241")

	s.App = lipgloss.NewStyle().
		Margin(1, 2)

	s.ServerName = lipgloss.NewStyle().
		Height(1).
		MarginLeft(1).
		MarginBottom(1).
		Padding(0, 1).
		Background(lipgloss.Color("57")).
		Foreground(lipgloss.Color("229")).
		Bold(true)

	s.TopLevelNormalTab = lipgloss.NewStyle().
		MarginRight(2)

	s.TopLevelActiveTab = s.TopLevelNormalTab.Copy().
		Foreground(lipgloss.Color("36"))

	s.TopLevelActiveTabDot = lipgloss.NewStyle().
		Foreground(lipgloss.Color("36"))

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

	s.RepoSelector.Active.Base = s.RepoSelector.Normal.Base.Copy().
		BorderStyle(lipgloss.Border{Left: "┃"}).
		BorderForeground(lipgloss.Color("176"))

	s.RepoSelector.Active.Title = s.RepoSelector.Normal.Title.Copy().
		Foreground(lipgloss.Color("212"))

	s.RepoSelector.Active.Desc = s.RepoSelector.Normal.Desc.Copy().
		Foreground(lipgloss.Color("246"))

	s.RepoSelector.Active.Updated = s.RepoSelector.Normal.Updated.Copy().
		Foreground(lipgloss.Color("212"))

	s.RepoSelector.Active.Command = s.RepoSelector.Normal.Command.Copy().
		Foreground(lipgloss.Color("204"))

	s.MenuItem = lipgloss.NewStyle().
		PaddingLeft(1).
		Border(lipgloss.Border{
			Left: " ",
		}, false, false, false, true).
		Height(3)

	s.MenuLastUpdate = lipgloss.NewStyle().
		Foreground(lipgloss.Color("241")).
		Align(lipgloss.Right)

	s.Repo.Base = lipgloss.NewStyle()

	s.Repo.Title = lipgloss.NewStyle().
		Padding(0, 2)

	s.Repo.Command = lipgloss.NewStyle().
		Foreground(lipgloss.Color("168"))

	s.Repo.Body = lipgloss.NewStyle().
		Margin(1, 0)

	s.Repo.Header = lipgloss.NewStyle().
		Height(2).
		Border(lipgloss.NormalBorder(), false, false, true, false).
		BorderForeground(lipgloss.Color("236"))

	s.Repo.HeaderName = lipgloss.NewStyle().
		Foreground(lipgloss.Color("212")).
		Bold(true)

	s.Repo.HeaderDesc = lipgloss.NewStyle().
		Foreground(lipgloss.Color("243"))

	s.Footer = lipgloss.NewStyle().
		MarginTop(1).
		Padding(0, 1).
		Height(1)

	s.Branch = lipgloss.NewStyle().
		Foreground(lipgloss.Color("203")).
		Background(lipgloss.Color("236")).
		Padding(0, 1)

	s.HelpKey = lipgloss.NewStyle().
		Foreground(lipgloss.Color("241"))

	s.HelpValue = lipgloss.NewStyle().
		Foreground(lipgloss.Color("239"))

	s.HelpDivider = lipgloss.NewStyle().
		Foreground(lipgloss.Color("237")).
		SetString(" • ")

	s.URLStyle = lipgloss.NewStyle().
		MarginLeft(1).
		Foreground(lipgloss.Color("168"))

	s.Error = lipgloss.NewStyle().
		MarginTop(2)

	s.ErrorTitle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("230")).
		Background(lipgloss.Color("204")).
		Bold(true).
		Padding(0, 1)

	s.ErrorBody = lipgloss.NewStyle().
		Foreground(lipgloss.Color("252")).
		MarginLeft(2)

	s.AboutNoReadme = lipgloss.NewStyle().
		MarginTop(1).
		MarginLeft(2).
		Foreground(lipgloss.Color("242"))

	s.LogItem.Normal.Base = lipgloss.NewStyle().
		Border(lipgloss.Border{
			Left: " ",
		}, false, false, false, true).
		PaddingLeft(1)

	s.LogItem.Active.Base = s.LogItem.Normal.Base.Copy().
		Border(lipgloss.Border{
			Left: "┃",
		}, false, false, false, true).
		BorderForeground(selectorColor)

	s.LogItem.Active.Hash = s.LogItem.Normal.Hash.Copy().
		Foreground(hashColor)

	s.LogItem.Active.Hash = lipgloss.NewStyle().
		Bold(true).
		Foreground(highlightColor)

	s.LogItem.Normal.Title = lipgloss.NewStyle().
		Foreground(lipgloss.Color("105"))

	s.LogItem.Active.Title = lipgloss.NewStyle().
		Foreground(highlightColor).
		Bold(true)

	s.LogItem.Normal.Desc = lipgloss.NewStyle().
		Foreground(lipgloss.Color("246"))

	s.LogItem.Active.Desc = lipgloss.NewStyle().
		Foreground(lipgloss.Color("95"))

	s.LogItem.Active.Keyword = s.LogItem.Active.Desc.Copy().
		Foreground(highlightColorDim)

	s.LogItem.Normal.Hash = lipgloss.NewStyle().
		Foreground(hashColor)

	s.LogItem.Active.Hash = lipgloss.NewStyle().
		Foreground(highlightColor)

	s.Log.Commit = lipgloss.NewStyle().
		Margin(0, 2)

	s.Log.CommitHash = lipgloss.NewStyle().
		Foreground(hashColor).
		Bold(true)

	s.Log.CommitBody = lipgloss.NewStyle().
		MarginTop(1).
		MarginLeft(2)

	s.Log.CommitStatsAdd = lipgloss.NewStyle().
		Foreground(lipgloss.Color("42")).
		Bold(true)

	s.Log.CommitStatsDel = lipgloss.NewStyle().
		Foreground(lipgloss.Color("203")).
		Bold(true)

	s.Log.Paginator = lipgloss.NewStyle().
		Margin(0).
		Align(lipgloss.Center)

	s.Ref.Normal.Item = lipgloss.NewStyle()

	s.Ref.ItemSelector = lipgloss.NewStyle().
		Foreground(selectorColor).
		SetString("> ")

	s.Ref.Active.Item = lipgloss.NewStyle().
		Foreground(highlightColorDim)

	s.Ref.ItemBranch = lipgloss.NewStyle()

	s.Ref.Normal.ItemTag = lipgloss.NewStyle().
		Foreground(lipgloss.Color("39"))

	s.Ref.Active.ItemTag = lipgloss.NewStyle().
		Bold(true).
		Foreground(highlightColor)

	s.Ref.Active.Item = lipgloss.NewStyle().
		Bold(true).
		Foreground(highlightColor)

	s.Ref.Paginator = s.Log.Paginator.Copy()

	s.Tree.Selector = s.Tree.Normal.FileName.Copy().
		Width(1).
		Foreground(selectorColor)

	s.Tree.Normal.FileName = lipgloss.NewStyle().
		MarginLeft(1)

	s.Tree.Active.FileName = s.Tree.Normal.FileName.Copy().
		Bold(true).
		Foreground(highlightColor)

	s.Tree.Normal.FileDir = lipgloss.NewStyle().
		Foreground(lipgloss.Color("39"))

	s.Tree.Active.FileDir = lipgloss.NewStyle().
		Foreground(highlightColor)

	s.Tree.Normal.FileMode = s.Tree.Active.FileName.Copy().
		Width(10).
		Foreground(lipgloss.Color("243"))

	s.Tree.Active.FileMode = s.Tree.Normal.FileMode.Copy().
		Foreground(highlightColorDim)

	s.Tree.Normal.FileSize = s.Tree.Normal.FileName.Copy().
		Foreground(lipgloss.Color("243"))

	s.Tree.Active.FileSize = s.Tree.Normal.FileName.Copy().
		Foreground(highlightColorDim)

	s.Tree.FileContent = lipgloss.NewStyle()

	s.Tree.Paginator = s.Log.Paginator.Copy()

	s.Tree.NoItems = s.AboutNoReadme.Copy()

	s.Spinner = lipgloss.NewStyle().
		MarginTop(1).
		MarginLeft(2).
		Foreground(lipgloss.Color("205"))

	s.CodeNoContent = lipgloss.NewStyle().
		SetString("No Content.").
		MarginTop(1).
		MarginLeft(2).
		Foreground(lipgloss.Color("242"))

	s.StatusBar = lipgloss.NewStyle().
		Height(1)

	s.StatusBarKey = lipgloss.NewStyle().
		Bold(true).
		Padding(0, 1).
		Background(lipgloss.Color("206")).
		Foreground(lipgloss.Color("228"))

	s.StatusBarValue = lipgloss.NewStyle().
		Padding(0, 1).
		Background(lipgloss.Color("235")).
		Foreground(lipgloss.Color("243"))

	s.StatusBarInfo = lipgloss.NewStyle().
		Padding(0, 1).
		Background(lipgloss.Color("212")).
		Foreground(lipgloss.Color("230"))

	s.StatusBarBranch = lipgloss.NewStyle().
		Padding(0, 1).
		Background(lipgloss.Color("62")).
		Foreground(lipgloss.Color("230"))

	s.StatusBarHelp = lipgloss.NewStyle().
		Padding(0, 1).
		Background(lipgloss.Color("237")).
		Foreground(lipgloss.Color("243"))

	s.Tabs = lipgloss.NewStyle().
		Height(1)

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
