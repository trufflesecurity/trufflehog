package sources

import (
	tea "github.com/charmbracelet/bubbletea"

	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/components/form"
)

// FormAdapter wraps a Definition + form.Form so that the existing
// source_configure tab components can consume a uniform tea.Model shape while
// still getting a structured []string arg vector out of Cmd().
//
// Cmd() returns the subcommand (Definition.Command) followed by the flag
// vector produced by the form and any ExtraArgs. This matches the pre-overhaul
// string contract where CmdModel.Cmd() included the subcommand token.
type FormAdapter struct {
	def  Definition
	form *form.Form
}

// NewFormAdapter builds an adapter for the given Definition.
func NewFormAdapter(def Definition) *FormAdapter {
	return &FormAdapter{
		def:  def,
		form: form.New(def.Fields, def.Constraints...),
	}
}

// Definition returns the underlying Definition.
func (a *FormAdapter) Definition() Definition { return a.def }

// Form returns the underlying form container.
func (a *FormAdapter) Form() *form.Form { return a.form }

// Init satisfies tea.Model.
func (a *FormAdapter) Init() tea.Cmd { return nil }

// Update delegates to the inner form.
func (a *FormAdapter) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	f, cmd := a.form.Update(msg)
	a.form = f
	return a, cmd
}

// View renders the inner form.
func (a *FormAdapter) View() string { return a.form.View() }

// Cmd returns the kingpin-style arg vector for this source's field values,
// prefixed with the Definition.Command subcommand token when set.
func (a *FormAdapter) Cmd() []string {
	var args []string
	if a.def.Command != "" {
		args = append(args, a.def.Command)
	}
	if a.def.BuildArgs != nil {
		args = append(args, a.def.BuildArgs(a.form.Values())...)
	} else {
		args = append(args, a.form.Args()...)
	}
	if len(a.def.ExtraArgs) > 0 {
		args = append(args, a.def.ExtraArgs...)
	}
	return args
}

// Summary returns the human-readable recap for this source.
func (a *FormAdapter) Summary() string { return a.form.Summary() }

// Valid reports whether the underlying form validates.
func (a *FormAdapter) Valid() bool { return a.form.Valid() }

// Resize forwards to the form.
func (a *FormAdapter) Resize(w, h int) { a.form.Resize(w, h) }
