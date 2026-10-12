package form

import (
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/theme"
)

// TextField is a free-text input backed by bubbles/textinput. It adds a
// label, optional help line, and a validation error slot.
type TextField struct {
	spec  FieldSpec
	input textinput.Model
	err   string
	width int
}

// NewTextField constructs a TextField for the given spec.
func NewTextField(spec FieldSpec) *TextField {
	ti := textinput.New()
	ti.Placeholder = spec.Placeholder
	ti.Prompt = "❯ "
	ti.CharLimit = 0
	ti.SetValue(spec.Default)
	return &TextField{spec: spec, input: ti}
}

// NewSecretField is a TextField with redacted echoing.
func NewSecretField(spec FieldSpec) *TextField {
	t := NewTextField(spec)
	t.input.EchoMode = textinput.EchoPassword
	t.input.EchoCharacter = '•'
	return t
}

// Spec returns the underlying FieldSpec.
func (t *TextField) Spec() FieldSpec { return t.spec }

// Value returns the current input value.
func (t *TextField) Value() string { return t.input.Value() }

// SetValue overwrites the input value.
func (t *TextField) SetValue(v string) { t.input.SetValue(v) }

// Focus transfers focus to the input.
func (t *TextField) Focus() tea.Cmd { return t.input.Focus() }

// Blur removes focus from the input and runs validators.
func (t *TextField) Blur() {
	t.input.Blur()
	_ = t.Validate()
}

// Focused reports whether the input currently has focus.
func (t *TextField) Focused() bool { return t.input.Focused() }

// Update delegates to the underlying textinput.
func (t *TextField) Update(msg tea.Msg) (Field, tea.Cmd) {
	var cmd tea.Cmd
	t.input, cmd = t.input.Update(msg)
	return t, cmd
}

// View renders the label, input, help, and any validation error.
func (t *TextField) View() string {
	styles := theme.DefaultStyles()
	var b strings.Builder
	label := t.spec.Label
	if label == "" {
		label = t.spec.Key
	}
	b.WriteString(styles.Bold.Render(label))
	b.WriteString("\n")
	b.WriteString(t.input.View())
	b.WriteString("\n")
	if t.err != "" {
		b.WriteString(styles.Error.Render("× " + t.err))
		b.WriteString("\n")
	} else if t.spec.Help != "" {
		b.WriteString(styles.Hint.Render(t.spec.Help))
		b.WriteString("\n")
	}
	b.WriteString("\n")
	return b.String()
}

// Error returns the most recent validation error message.
func (t *TextField) Error() string { return t.err }

// Validate runs the spec's Validators against the current value.
func (t *TextField) Validate() error {
	t.err = ""
	for _, v := range t.spec.Validators {
		if err := v(t.input.Value()); err != nil {
			t.err = err.Error()
			return err
		}
	}
	return nil
}

// SetWidth hints the input width. bubbles/textinput pads the value with
// trailing spaces up to Width, so we cap it to avoid painting hundreds of
// columns of padding on wide terminals while still leaving headroom under
// the content area on narrower ones.
func (t *TextField) SetWidth(w int) {
	t.width = w
	width := w - 6
	if width > 80 {
		width = 80
	}
	if width < 10 {
		width = 10
	}
	t.input.Width = width
}
