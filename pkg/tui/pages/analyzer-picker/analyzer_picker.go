// Package analyzerpicker is the list of available analyzer types.
package analyzerpicker

import (
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/app"
	analyzerform "github.com/trufflesecurity/trufflehog/v3/pkg/tui/pages/analyzer-form"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/theme"
)

// ID is the stable page id.
const ID = app.PageAnalyzerPicker

type item string

func (i item) FilterValue() string { return string(i) }
func (i item) Title() string       { return string(i) }
func (i item) Description() string { return "" }

// Page is the tea.Model implementation.
type Page struct {
	list   list.Model
	styles *theme.Styles
	keymap *theme.KeyMap
}

// New constructs the analyzer picker.
func New(styles *theme.Styles, keymap *theme.KeyMap, _ any) *Page {
	all := analyzers.AvailableAnalyzers()
	items := make([]list.Item, len(all))
	for i, a := range all {
		items[i] = item(a)
	}
	delegate := list.NewDefaultDelegate()
	delegate.ShowDescription = false
	delegate.SetSpacing(0)
	l := list.New(items, delegate, 0, 0)
	l.Title = "Select an analyzer type"
	l.Styles.Title = styles.Title
	l.SetShowStatusBar(false)
	return &Page{list: l, styles: styles, keymap: keymap}
}

func (p *Page) ID() app.PageID { return ID }

func (p *Page) Init() tea.Cmd { return nil }

func (p *Page) Update(msg tea.Msg) (app.Page, tea.Cmd) {
	switch msg := msg.(type) {
	case app.ResizeMsg:
		p.list.SetSize(msg.Width, msg.Height)
		return p, nil
	case tea.KeyMsg:
		if p.list.SettingFilter() {
			break
		}
		if key.Matches(msg, p.keymap.Select) {
			sel, ok := p.list.SelectedItem().(item)
			if !ok {
				return p, nil
			}
			return p, func() tea.Msg {
				return app.PushMsg{ID: app.PageAnalyzerForm, Data: analyzerform.Data{
					KeyType: string(sel),
				}}
			}
		}
	}
	var cmd tea.Cmd
	p.list, cmd = p.list.Update(msg)
	return p, cmd
}

func (p *Page) View() string { return p.list.View() }

func (p *Page) SetSize(width, height int) {
	p.list.SetSize(width, height)
}

func (p *Page) Help() []key.Binding {
	return []key.Binding{p.keymap.UpDown, p.keymap.Select}
}

func (p *Page) AllowQKey() bool { return false }
