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
//
// Focus model: f.focused ranges over [0, len(fields)]. Indices 0..len-1 are
// the field widgets; len(fields) is the submit button stop. Pressing enter on
// a field advances focus; pressing enter on the submit button validates and
// emits SubmitMsg.
type Form struct {
	fields      []Field
	constraints []Constraint
	focused     int
	topError    string
	width       int
	height      int
	submitMsg   string
	submitKeys  key.Binding
	nextKeys    key.Binding
	prevKeys    key.Binding
}

// New constructs a Form from the given field specs and optional cross-field
// constraints. The default submit-button label is "Next"; callers should
// override via SetSubmitMsg when the action is more specific (e.g. "Run
// TruffleHog Analyze").
func New(specs []FieldSpec, constraints ...Constraint) *Form {
	f := &Form{
		constraints: constraints,
		submitMsg:   "Next",
		submitKeys:  key.NewBinding(key.WithKeys("ctrl+s")),
		nextKeys:    key.NewBinding(key.WithKeys("down")),
		prevKeys:    key.NewBinding(key.WithKeys("up")),
	}
	f.fields = make([]Field, 0, len(specs))
	for _, s := range specs {
		f.fields = append(f.fields, newField(s))
	}
	f.focused = -1
	f.focusNext()
	return f
}

// SetSubmitMsg sets the label rendered on the submit button. Empty defaults
// to "Next".
func (f *Form) SetSubmitMsg(msg string) {
	if msg == "" {
		msg = "Next"
	}
	f.submitMsg = msg
}

// submitFocused reports whether focus is currently on the submit button.
func (f *Form) submitFocused() bool { return f.focused == len(f.fields) }

func (f *Form) submitCmd() tea.Cmd {
	values := f.Values()
	args := f.Args()
	return func() tea.Msg { return SubmitMsg{Values: values, Args: args} }
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
	f.blurCurrent()
	f.focused++
	if f.focused > len(f.fields) {
		f.focused = 0
	}
	if f.focused < len(f.fields) {
		f.fields[f.focused].Focus()
	}
}

func (f *Form) focusPrev() {
	if len(f.fields) == 0 {
		return
	}
	f.blurCurrent()
	f.focused--
	if f.focused < 0 {
		f.focused = len(f.fields)
	}
	if f.focused < len(f.fields) {
		f.fields[f.focused].Focus()
	}
}

func (f *Form) blurCurrent() {
	if f.focused >= 0 && f.focused < len(f.fields) {
		f.fields[f.focused].Blur()
	}
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
			if f.submitFocused() {
				if !f.Valid() {
					return f, nil
				}
				return f, f.submitCmd()
			}
			f.focusNext()
			return f, nil
		case key.Matches(km, f.submitKeys):
			if !f.Valid() {
				return f, nil
			}
			return f, f.submitCmd()
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
// form renders the top-level constraint error above all fields and the
// submit button below them. The button's brand styling makes the action
// discoverable — pressing enter on the last field advances to it, not
// straight to submit.
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
	label := "[ " + f.submitMsg + " ]"
	if f.submitFocused() {
		b.WriteString(styles.ButtonFocused.Render(label))
	} else {
		b.WriteString(styles.Button.Render(label))
	}
	b.WriteString("\n")
	return lipgloss.NewStyle().Render(b.String())
}
