// Package analyzerform is the per-analyzer credential entry form. On
// submit it hands control to analyzer.Run via app.RunAnalyzerMsg.
package analyzerform

import (
	"strings"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/app"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/components/form"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/theme"
)

// ID is the stable page id.
const ID = app.PageAnalyzerForm

// Data is the payload passed via PushMsg to seed the form.
type Data struct {
	KeyType string
}

// Page is the tea.Model implementation.
type Page struct {
	styles  *theme.Styles
	keymap  *theme.KeyMap
	keyType string
	form    *form.Form
}

// New constructs an analyzer form for the given key type. Unknown key types
// fall back to a single-secret form.
func New(styles *theme.Styles, keymap *theme.KeyMap, data any) *Page {
	d, _ := data.(Data)
	return &Page{
		styles:  styles,
		keymap:  keymap,
		keyType: d.KeyType,
		form:    form.New(specsFor(d.KeyType)),
	}
}

// specsFor returns the field specs for a given analyzer key type.
func specsFor(keyType string) []form.FieldSpec {
	secret := form.FieldSpec{Key: "key", Label: "Secret", Kind: form.KindSecret, Validators: []form.Validate{form.Required()}}
	logFile := form.FieldSpec{Key: "log_file", Label: "Log file", Help: "Log HTTP requests that analysis performs to this file", Kind: form.KindText}

	var specs []form.FieldSpec
	switch strings.ToLower(keyType) {
	case "twilio":
		specs = []form.FieldSpec{
			{Key: "sid", Label: "SID", Kind: form.KindText, Validators: []form.Validate{form.Required()}},
			{Key: "key", Label: "Token", Kind: form.KindSecret, Validators: []form.Validate{form.Required()}},
		}
	case "shopify":
		specs = []form.FieldSpec{
			{Key: "key", Label: "Secret", Kind: form.KindSecret, Validators: []form.Validate{form.Required()}},
			{Key: "url", Label: "Shopify URL", Kind: form.KindText, Validators: []form.Validate{form.Required()}},
		}
	case "dockerhub":
		specs = []form.FieldSpec{
			{Key: "username", Label: "Username", Kind: form.KindText, Validators: []form.Validate{form.Required()}},
			{Key: "pat", Label: "Token (PAT)", Kind: form.KindSecret, Validators: []form.Validate{form.Required()}},
		}
	case "planetscale":
		specs = []form.FieldSpec{
			{Key: "id", Label: "Service Id", Kind: form.KindText, Validators: []form.Validate{form.Required()}},
			{Key: "token", Label: "Service Token", Kind: form.KindSecret, Validators: []form.Validate{form.Required()}},
		}
	case "plaid":
		specs = []form.FieldSpec{
			{Key: "secret", Label: "Secret", Kind: form.KindSecret, Validators: []form.Validate{form.Required()}},
			{Key: "id", Label: "Client ID", Kind: form.KindText, Validators: []form.Validate{form.Required()}},
			{Key: "token", Label: "Access Token", Kind: form.KindSecret, Validators: []form.Validate{form.Required()}},
		}
	case "datadog":
		specs = []form.FieldSpec{
			{Key: "api_key", Label: "API Key", Kind: form.KindSecret, Validators: []form.Validate{form.Required()}},
			{Key: "app_key", Label: "Application Key", Kind: form.KindSecret},
			{Key: "endpoint", Label: "Endpoint", Help: "Leave empty to auto-detect", Kind: form.KindText},
		}
	case "mux":
		specs = []form.FieldSpec{
			{Key: "secret", Label: "Secret", Kind: form.KindSecret, Validators: []form.Validate{form.Required()}},
			{Key: "key", Label: "Key", Kind: form.KindText, Validators: []form.Validate{form.Required()}},
		}
	case "databricks":
		specs = []form.FieldSpec{
			{Key: "token", Label: "Access Token", Kind: form.KindSecret, Validators: []form.Validate{form.Required()}},
			{Key: "domain", Label: "Domain", Kind: form.KindText, Validators: []form.Validate{form.Required()}},
		}
	case "jira":
		specs = []form.FieldSpec{
			{Key: "domain", Label: "Domain", Kind: form.KindText, Validators: []form.Validate{form.Required()}},
			{Key: "email", Label: "Email", Kind: form.KindText, Validators: []form.Validate{form.Required()}},
			{Key: "token", Label: "Token", Kind: form.KindSecret, Validators: []form.Validate{form.Required()}},
		}
	default:
		specs = []form.FieldSpec{secret}
	}
	return append(specs, logFile)
}

func (p *Page) ID() app.PageID { return ID }

func (p *Page) Init() tea.Cmd { return nil }

func (p *Page) Update(msg tea.Msg) (app.Page, tea.Cmd) {
	switch msg := msg.(type) {
	case app.ResizeMsg:
		p.form.Resize(msg.Width, msg.Height)
		return p, nil
	case form.SubmitMsg:
		return p, p.runAnalyzer(msg.Values)
	}
	f, cmd := p.form.Update(msg)
	p.form = f
	return p, cmd
}

func (p *Page) runAnalyzer(values map[string]string) tea.Cmd {
	logFile := values["log_file"]
	cfg := config.Config{LogFile: logFile, LoggingEnabled: logFile != ""}
	info := analyzer.SecretInfo{Cfg: &cfg, Parts: values}
	return func() tea.Msg {
		return app.RunAnalyzerMsg{Type: p.keyType, Info: info}
	}
}

func (p *Page) View() string {
	var b strings.Builder
	b.WriteString(p.styles.Title.Render("Configuring " + p.keyType + " analyzer"))
	b.WriteString("\n\n")
	b.WriteString(p.form.View())
	b.WriteString("\n⚠️  Running TruffleHog Analyze will send a lot of requests ⚠️\n")
	b.WriteString("🚧 Please confirm you have permission to run this analyzer 🚧\n")
	return b.String()
}

func (p *Page) SetSize(width, height int) { p.form.Resize(width, height) }

func (p *Page) Help() []key.Binding {
	return []key.Binding{p.keymap.UpDown, p.keymap.Select}
}

// AllowQKey is false because the form accepts free-text input that may
// include the letter q.
func (p *Page) AllowQKey() bool { return false }
