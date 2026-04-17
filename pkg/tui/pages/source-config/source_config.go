// Package sourceconfig hosts the three-tab source configuration flow:
// per-source fields, TruffleHog-wide flags, then a review/run step that
// hands control back to kingpin via app.ExitMsg.
package sourceconfig

import (
	"runtime"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/app"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/components/form"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/theme"
)

// ID is the stable page id.
const ID = app.PageSourceConfig

// Data is the payload passed via PushMsg to seed the page. SourceTitle is
// resolved through sources.ByTitle.
type Data struct {
	SourceTitle string
}

type tabIndex int

const (
	tabSource tabIndex = iota
	tabTrufflehog
	tabRun
)

var tabLabels = []string{
	"1. Source Configuration",
	"2. TruffleHog Configuration",
	"3. Run",
}

// Page is the tea.Model implementation.
type Page struct {
	styles *theme.Styles
	keymap *theme.KeyMap

	def           sources.Definition
	sourceAdapter *sources.FormAdapter
	truffleForm   *form.Form

	active tabIndex
	width  int
	height int
	unknown bool
}

// New constructs a source-config page. If the referenced source isn't in
// the registry the page renders a "not found" error and nothing else.
func New(styles *theme.Styles, keymap *theme.KeyMap, data any) *Page {
	d, _ := data.(Data)
	def, ok := sources.ByTitle(d.SourceTitle)
	if !ok {
		return &Page{styles: styles, keymap: keymap, unknown: true}
	}
	return &Page{
		styles:        styles,
		keymap:        keymap,
		def:           def,
		sourceAdapter: sources.NewFormAdapter(def),
		truffleForm:   newTruffleForm(),
	}
}

// newTruffleForm builds the TruffleHog-wide flags form. Booleans render as
// checkboxes; --only-verified expands to --results=verified.
func newTruffleForm() *form.Form {
	specs := []form.FieldSpec{
		{Key: "json", Label: "JSON output", Help: "Output results as JSON", Kind: form.KindCheckbox, Emit: form.EmitPresence},
		{Key: "no-verification", Label: "Skip Verification", Help: "Skip checking if suspected secrets are real", Kind: form.KindCheckbox, Emit: form.EmitPresence},
		{Key: "only-verified", Label: "Verified results only", Help: "Return only verified results", Kind: form.KindCheckbox, Emit: form.EmitConstant, Constant: []string{"--results=verified"}},
		{Key: "exclude-detectors", Label: "Exclude detectors", Help: "Comma-separated detector IDs to exclude.", Kind: form.KindText, Emit: form.EmitLongFlagEq, Transform: stripSpaces},
		{Key: "concurrency", Label: "Concurrency", Help: "Number of concurrent workers", Kind: form.KindText, Placeholder: strconv.Itoa(runtime.NumCPU()), Emit: form.EmitLongFlagEq, Validators: []form.Validate{form.Integer(1, 1 << 20)}},
	}
	return form.New(specs)
}

func stripSpaces(v string) string { return strings.ReplaceAll(v, " ", "") }

func (p *Page) ID() app.PageID { return ID }

func (p *Page) Init() tea.Cmd { return nil }

func (p *Page) Update(msg tea.Msg) (app.Page, tea.Cmd) {
	if p.unknown {
		return p, nil
	}
	switch msg := msg.(type) {
	case app.ResizeMsg:
		p.width = msg.Width
		p.height = msg.Height
		p.sourceAdapter.Resize(msg.Width, msg.Height)
		p.truffleForm.Resize(msg.Width, msg.Height)
		return p, nil
	case tea.KeyMsg:
		if key.Matches(msg, p.keymap.Section) {
			p.advanceTab(msg.String() == "shift+tab")
			return p, nil
		}
		if p.active == tabRun && msg.Type == tea.KeyEnter {
			return p, p.runCmd()
		}
	case form.SubmitMsg:
		p.advanceTab(false)
		return p, nil
	}
	return p.forwardToActive(msg)
}

func (p *Page) advanceTab(back bool) {
	switch {
	case back && p.active > tabSource:
		p.active--
	case !back && p.active < tabRun:
		p.active++
	}
}

func (p *Page) forwardToActive(msg tea.Msg) (app.Page, tea.Cmd) {
	switch p.active {
	case tabSource:
		_, cmd := p.sourceAdapter.Update(msg)
		return p, cmd
	case tabTrufflehog:
		f, cmd := p.truffleForm.Update(msg)
		p.truffleForm = f
		return p, cmd
	}
	return p, nil
}

// truffleCmd returns the truffle flag tokens, delegating to the shared
// form.BuildArgs via form.Args().
func (p *Page) truffleCmd() []string { return p.truffleForm.Args() }

func (p *Page) runCmd() tea.Cmd {
	args := append([]string{}, p.sourceAdapter.Cmd()...)
	args = append(args, p.truffleCmd()...)
	return func() tea.Msg { return app.ExitMsg{Args: args} }
}

func (p *Page) View() string {
	if p.unknown {
		return p.styles.Error.Render("Unknown source.")
	}
	var b strings.Builder
	b.WriteString(p.renderTabs())
	b.WriteString("\n\n")
	switch p.active {
	case tabSource:
		b.WriteString(p.sourceView())
	case tabTrufflehog:
		b.WriteString(p.truffleView())
	case tabRun:
		b.WriteString(p.runView())
	}
	return b.String()
}

func (p *Page) renderTabs() string {
	parts := make([]string, 0, len(tabLabels)*2)
	for i, label := range tabLabels {
		style := p.styles.TabInactive
		if tabIndex(i) == p.active {
			style = p.styles.TabActive
		}
		parts = append(parts, style.Render(label))
		if i != len(tabLabels)-1 {
			parts = append(parts, p.styles.TabSeparator.String())
		}
	}
	return lipgloss.JoinHorizontal(lipgloss.Top, parts...)
}

func (p *Page) sourceView() string {
	var b strings.Builder
	b.WriteString(p.styles.Bold.Render("Configuring "))
	b.WriteString(p.styles.Primary.Render(p.def.Title))
	b.WriteString("\n")
	b.WriteString(p.styles.Hint.Render("* required field"))
	b.WriteString("\n\n")
	if p.def.Note != "" {
		b.WriteString("⭐ " + p.def.Note + " ⭐\n\n")
	}
	b.WriteString(p.sourceAdapter.View())
	return b.String()
}

func (p *Page) truffleView() string {
	var b strings.Builder
	b.WriteString(p.styles.Bold.Render("Configuring "))
	b.WriteString(p.styles.Primary.Render("TruffleHog"))
	b.WriteString("\n")
	b.WriteString(p.styles.Hint.Render("You can skip this and run with defaults"))
	b.WriteString("\n\n")
	b.WriteString(p.truffleForm.View())
	return b.String()
}

func (p *Page) runView() string {
	var b strings.Builder
	b.WriteString(p.styles.Bold.Render("Ready to run TruffleHog for " + p.def.Title))
	b.WriteString("\n\n🔎 Source configuration\n")
	b.WriteString(indentOrDefault(p.sourceAdapter.Summary()))
	b.WriteString("\n🐽 TruffleHog configuration\n")
	b.WriteString(indentOrDefault(p.truffleForm.Summary()))
	b.WriteString("\nGenerated command:\n")
	b.WriteString(p.styles.Code.Render(renderCommand(p.sourceAdapter.Cmd(), p.truffleCmd())))
	b.WriteString("\n\n")
	b.WriteString(p.styles.Primary.Render("[ press enter to run ]"))
	return b.String()
}

func indentOrDefault(s string) string {
	s = strings.TrimRight(s, "\n")
	if s == "" {
		return "\tRunning with defaults\n"
	}
	return s + "\n"
}

// renderCommand prints the final argv with single-quoted tokens when they
// contain whitespace so users can copy/paste the result.
func renderCommand(source, truffle []string) string {
	parts := []string{"trufflehog"}
	parts = append(parts, quoteTokens(source)...)
	parts = append(parts, quoteTokens(truffle)...)
	return strings.Join(parts, " ")
}

func quoteTokens(ts []string) []string {
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		if strings.ContainsAny(t, " \t") {
			out = append(out, "'"+t+"'")
			continue
		}
		out = append(out, t)
	}
	return out
}

func (p *Page) SetSize(width, height int) {
	p.width = width
	p.height = height
	if p.sourceAdapter != nil {
		p.sourceAdapter.Resize(width, height)
	}
	if p.truffleForm != nil {
		p.truffleForm.Resize(width, height)
	}
}

func (p *Page) Help() []key.Binding {
	return []key.Binding{p.keymap.UpDown, p.keymap.Section, p.keymap.Select}
}

// AllowQKey is false because every tab in this flow accepts free text.
func (p *Page) AllowQKey() bool { return false }
