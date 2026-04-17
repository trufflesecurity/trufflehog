// Package sourcepicker is the source selection list. Selecting an OSS source
// pushes source-config; selecting an Enterprise source pushes a contact link
// card.
package sourcepicker

import (
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/app"
	linkcard "github.com/trufflesecurity/trufflehog/v3/pkg/tui/pages/link-card"
	sourceconfig "github.com/trufflesecurity/trufflehog/v3/pkg/tui/pages/source-config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/theme"
)

// ID is the stable page id.
const ID = app.PageSourcePicker

// enterpriseSources is the advertised-only list. The registry only contains
// OSS sources; these are appended to the list so users can see what's
// available behind the paywall.
var enterpriseSources = []sources.Definition{
	{Title: "Artifactory", Description: "Scan JFrog Artifactory packages.", Tier: sources.TierEnterprise},
	{Title: "Azure Repos", Description: "Scan Microsoft Azure repositories.", Tier: sources.TierEnterprise},
	{Title: "BitBucket", Description: "Scan Atlassian's Git-based source code repository hosting service.", Tier: sources.TierEnterprise},
	{Title: "Buildkite", Description: "Scan Buildkite, a CI/CD platform.", Tier: sources.TierEnterprise},
	{Title: "Confluence", Description: "Scan Atlassian's web-based wiki and knowledge base.", Tier: sources.TierEnterprise},
	{Title: "Gerrit", Description: "Scan Gerrit, a code collaboration tool", Tier: sources.TierEnterprise},
	{Title: "Jira", Description: "Scan Atlassian's issue & project tracking software.", Tier: sources.TierEnterprise},
	{Title: "Slack", Description: "Scan Slack, a messaging and communication platform.", Tier: sources.TierEnterprise},
	{Title: "Microsoft Teams", Description: "Scan Microsoft Teams, a messaging and communication platform.", Tier: sources.TierEnterprise},
	{Title: "Microsoft Sharepoint", Description: "Scan Microsoft Sharepoint, a collaboration and document management platform.", Tier: sources.TierEnterprise},
	{Title: "Google Drive", Description: "Scan Google Drive, a cloud-based storage and file sync service.", Tier: sources.TierEnterprise},
}

type item struct {
	def sources.Definition
}

func (i item) FilterValue() string { return i.def.Title + i.def.Description }

func (i item) Title() string {
	if i.def.Tier == sources.TierEnterprise {
		return "💸 " + i.def.Title
	}
	return i.def.Title
}

func (i item) Description() string {
	if i.def.Tier == sources.TierEnterprise {
		return i.def.Description + " (Enterprise only)"
	}
	return i.def.Description
}

// Page is the tea.Model implementation.
type Page struct {
	list   list.Model
	styles *theme.Styles
	keymap *theme.KeyMap
}

// New constructs the source picker.
func New(styles *theme.Styles, keymap *theme.KeyMap, _ any) *Page {
	items := buildItems()
	delegate := list.NewDefaultDelegate()
	l := list.New(items, delegate, 0, 0)
	l.Title = "Sources"
	l.Styles.Title = styles.Title
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(true)
	return &Page{list: l, styles: styles, keymap: keymap}
}

func buildItems() []list.Item {
	defs := sources.All()
	out := make([]list.Item, 0, len(defs)+len(enterpriseSources))
	for _, d := range defs {
		out = append(out, item{def: d})
	}
	for _, d := range enterpriseSources {
		out = append(out, item{def: d})
	}
	return out
}

func (p *Page) ID() app.PageID { return ID }

func (p *Page) Init() tea.Cmd { return nil }

func (p *Page) Update(msg tea.Msg) (app.Page, tea.Cmd) {
	switch msg := msg.(type) {
	case app.ResizeMsg:
		p.list.SetSize(msg.Width, msg.Height)
		return p, nil
	case tea.KeyMsg:
		if p.list.FilterState() == list.Filtering {
			break
		}
		if key.Matches(msg, p.keymap.Select) {
			return p, p.choose()
		}
	}
	var cmd tea.Cmd
	p.list, cmd = p.list.Update(msg)
	return p, cmd
}

func (p *Page) choose() tea.Cmd {
	selected, ok := p.list.SelectedItem().(item)
	if !ok {
		return nil
	}
	if selected.def.Tier == sources.TierEnterprise {
		return func() tea.Msg {
			return app.PushMsg{ID: app.PageLinkCard, Data: linkcard.Data{
				Title: "Interested in TruffleHog enterprise?",
				URL:   "https://trufflesecurity.com/contact",
			}}
		}
	}
	return func() tea.Msg {
		return app.PushMsg{ID: app.PageSourceConfig, Data: sourceconfig.Data{
			SourceTitle: selected.def.Title,
		}}
	}
}

func (p *Page) View() string { return p.list.View() }

func (p *Page) SetSize(width, height int) {
	p.list.SetSize(width, height)
}

func (p *Page) Help() []key.Binding {
	return []key.Binding{p.keymap.UpDown, p.keymap.Select}
}

// AllowQKey is false so the list's filter-by-text still accepts "q".
func (p *Page) AllowQKey() bool { return false }
