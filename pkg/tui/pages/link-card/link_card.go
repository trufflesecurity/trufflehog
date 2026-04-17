// Package linkcard is the shared single-link landing page (OSS repo +
// Enterprise contact). The only state is the text + the URL, so both cards
// share one implementation.
package linkcard

import (
	"strings"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/app"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/theme"
)

// ID is the stable page id.
const ID = app.PageLinkCard

// Data is the payload passed via PushMsg to seed a link card.
type Data struct {
	Title string
	URL   string
}

// Page is the tea.Model implementation.
type Page struct {
	data   Data
	styles *theme.Styles
}

// New constructs a link card. Data must be a Data value; zero value is
// handled gracefully.
func New(styles *theme.Styles, data any) *Page {
	d, _ := data.(Data)
	return &Page{data: d, styles: styles}
}

func (p *Page) ID() app.PageID { return ID }

func (p *Page) Init() tea.Cmd { return nil }

func (p *Page) Update(msg tea.Msg) (app.Page, tea.Cmd) { return p, nil }

func (p *Page) View() string {
	link := lipgloss.NewStyle().
		Foreground(theme.ColorLink).
		Render("🔗 " + p.data.URL)
	var b strings.Builder
	b.WriteString(p.data.Title)
	b.WriteString("\n")
	b.WriteString(link)
	return b.String()
}

func (p *Page) SetSize(width, height int) {}

func (p *Page) Help() []key.Binding { return nil }

func (p *Page) AllowQKey() bool { return true }
