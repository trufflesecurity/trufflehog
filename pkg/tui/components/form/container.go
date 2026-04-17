package form

import (
	"strings"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/theme"
)

// SubmitMsg is emitted by Form.Update when the user presses enter on a valid
// form. Parent pages listen for it to advance their flow.
type SubmitMsg struct {
	// Values maps FieldSpec.Key to the current value of each field.
	Values map[string]string
	// Args is the kingpin arg vector produced by Form.Args().
	Args []string
}

// Form is a container that wires a slice of FieldSpecs into working widgets,
// handles focus / submit, runs validators and constraints, and produces an
// arg vector via Args.
type Form struct {
	fields      []Field
	constraints []Constraint
	focused     int
	topError    string
	width       int
	height      int
	submitKeys  key.Binding
	nextKeys    key.Binding
	prevKeys    key.Binding
}

// New constructs a Form from the given field specs and optional cross-field
// constraints.
func New(specs []FieldSpec, constraints ...Constraint) *Form {
	f := &Form{
		constraints: constraints,
		submitKeys:  key.NewBinding(key.WithKeys("ctrl+s")),
		nextKeys:    key.NewBinding(key.WithKeys("tab", "down")),
		prevKeys:    key.NewBinding(key.WithKeys("shift+tab", "up")),
	}
	f.fields = make([]Field, 0, len(specs))
	for _, s := range specs {
		f.fields = append(f.fields, newField(s))
	}
	f.focused = -1
	f.focusNext()
	return f
}

// Fields returns the underlying field widgets. The slice shares the form's
// backing array and must not be mutated.
func (f *Form) Fields() []Field { return f.fields }

// Values returns a map from FieldSpec.Key to current value.
func (f *Form) Values() map[string]string {
	out := make(map[string]string, len(f.fields))
	for _, fd := range f.fields {
		out[fd.Spec().Key] = fd.Value()
	}
	return out
}

// Args returns the kingpin-style arg vector produced from the current values.
// The caller is responsible for prepending any subcommand name.
func (f *Form) Args() []string {
	specs := make([]FieldSpec, len(f.fields))
	for i, fd := range f.fields {
		specs[i] = fd.Spec()
	}
	return BuildArgs(specs, f.Values())
}

// Summary returns a human-readable recap of non-empty field values.
func (f *Form) Summary() string {
	var b strings.Builder
	for _, fd := range f.fields {
		v := fd.Value()
		if strings.TrimSpace(v) == "" {
			continue
		}
		label := fd.Spec().Label
		if label == "" {
			label = fd.Spec().Key
		}
		b.WriteString("\t")
		b.WriteString(label)
		b.WriteString(": ")
		b.WriteString(v)
		b.WriteString("\n")
	}
	return b.String()
}

// Valid runs every validator and every constraint and returns true if none
// produce an error. Side effect: per-field errors are stored on the
// individual widgets, and the form's top-level constraint error (if any) is
// stored too so View() can render it.
func (f *Form) Valid() bool {
	ok := true
	for _, fd := range f.fields {
		if err := fd.Validate(); err != nil {
			ok = false
		}
	}
	f.topError = ""
	for _, c := range f.constraints {
		if err := c(f.Values()); err != nil {
			ok = false
			if f.topError == "" {
				f.topError = err.Error()
			}
		}
	}
	return ok
}

func (f *Form) focusNext() {
	if len(f.fields) == 0 {
		return
	}
	if f.focused >= 0 && f.focused < len(f.fields) {
		f.fields[f.focused].Blur()
	}
	f.focused = (f.focused + 1) % len(f.fields)
	f.fields[f.focused].Focus()
}

func (f *Form) focusPrev() {
	if len(f.fields) == 0 {
		return
	}
	if f.focused >= 0 && f.focused < len(f.fields) {
		f.fields[f.focused].Blur()
	}
	f.focused = (f.focused - 1 + len(f.fields)) % len(f.fields)
	f.fields[f.focused].Focus()
}

// Update forwards keyboard events to the focused field, handling focus
// cycling and submission at the container level.
func (f *Form) Update(msg tea.Msg) (*Form, tea.Cmd) {
	if km, ok := msg.(tea.KeyMsg); ok {
		switch {
		case key.Matches(km, f.nextKeys):
			f.focusNext()
			return f, nil
		case key.Matches(km, f.prevKeys):
			f.focusPrev()
			return f, nil
		case km.String() == "enter":
			if f.focused < len(f.fields)-1 {
				f.focusNext()
				return f, nil
			}
			if !f.Valid() {
				return f, nil
			}
			return f, func() tea.Msg {
				return SubmitMsg{Values: f.Values(), Args: f.Args()}
			}
		case key.Matches(km, f.submitKeys):
			if !f.Valid() {
				return f, nil
			}
			return f, func() tea.Msg {
				return SubmitMsg{Values: f.Values(), Args: f.Args()}
			}
		}
	}
	if f.focused >= 0 && f.focused < len(f.fields) {
		var cmd tea.Cmd
		f.fields[f.focused], cmd = f.fields[f.focused].Update(msg)
		return f, cmd
	}
	return f, nil
}

// Resize stores the form dimensions and forwards the width to text inputs
// that care about it.
func (f *Form) Resize(w, h int) {
	f.width = w
	f.height = h
	for _, fd := range f.fields {
		if sizer, ok := fd.(interface{ SetWidth(int) }); ok {
			sizer.SetWidth(w)
		}
	}
}

// View renders the form. Each field renders its own label/help/error; the
// form renders the top-level constraint error above all fields.
func (f *Form) View() string {
	styles := theme.DefaultStyles()
	var b strings.Builder
	if f.topError != "" {
		b.WriteString(styles.Error.Render("× " + f.topError))
		b.WriteString("\n\n")
	}
	for _, fd := range f.fields {
		b.WriteString(fd.View())
	}
	return lipgloss.NewStyle().Render(b.String())
}
