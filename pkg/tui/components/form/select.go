package form

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/theme"
)

// SelectField is a single-select over FieldSpec.Options.
type SelectField struct {
	spec    FieldSpec
	index   int
	focused bool
	err     string
}

// NewSelectField constructs a SelectField for the given spec. If the spec's
// Default matches one of the option values, that option starts selected.
func NewSelectField(spec FieldSpec) *SelectField {
	s := &SelectField{spec: spec}
	for i, o := range spec.Options {
		if o.Value == spec.Default {
			s.index = i
			break
		}
	}
	return s
}

// Spec returns the underlying FieldSpec.
func (s *SelectField) Spec() FieldSpec { return s.spec }

// Value returns the currently selected option's Value.
func (s *SelectField) Value() string {
	if len(s.spec.Options) == 0 {
		return ""
	}
	if s.index < 0 || s.index >= len(s.spec.Options) {
		return ""
	}
	return s.spec.Options[s.index].Value
}

// SetValue selects the option whose Value matches v; a no-op if none does.
func (s *SelectField) SetValue(v string) {
	for i, o := range s.spec.Options {
		if o.Value == v {
			s.index = i
			return
		}
	}
}

// Focus marks the field as focused.
func (s *SelectField) Focus() tea.Cmd { s.focused = true; return nil }

// Blur removes focus.
func (s *SelectField) Blur() { s.focused = false }

// Focused reports whether the field has focus.
func (s *SelectField) Focused() bool { return s.focused }

// Update advances / reverses the selection on h/l, left/right.
func (s *SelectField) Update(msg tea.Msg) (Field, tea.Cmd) {
	if !s.focused || len(s.spec.Options) == 0 {
		return s, nil
	}
	if key, ok := msg.(tea.KeyMsg); ok {
		switch key.String() {
		case "left", "h":
			s.index = (s.index - 1 + len(s.spec.Options)) % len(s.spec.Options)
		case "right", "l", " ":
			s.index = (s.index + 1) % len(s.spec.Options)
		}
	}
	return s, nil
}

// View renders a horizontal pill group of the options.
func (s *SelectField) View() string {
	styles := theme.DefaultStyles()
	label := s.spec.Label
	if label == "" {
		label = s.spec.Key
	}
	var pills []string
	for i, o := range s.spec.Options {
		text := " " + o.Label + " "
		if i == s.index {
			if s.focused {
				pills = append(pills, styles.SelectedItem.Render(text))
			} else {
				pills = append(pills, styles.Bold.Render("["+o.Label+"]"))
			}
		} else {
			pills = append(pills, styles.Hint.Render(text))
		}
	}
	var b strings.Builder
	b.WriteString(styles.Bold.Render(label))
	b.WriteString("\n")
	prefix := "  "
	if s.focused {
		prefix = styles.Primary.Render("❯ ")
	}
	b.WriteString(prefix + strings.Join(pills, " "))
	b.WriteString("\n")
	if s.err != "" {
		b.WriteString(styles.Error.Render("× " + s.err))
		b.WriteString("\n")
	} else if s.spec.Help != "" {
		b.WriteString(styles.Hint.Render(s.spec.Help))
		b.WriteString("\n")
	}
	b.WriteString("\n")
	return b.String()
}

// Error returns the most recent validation error.
func (s *SelectField) Error() string { return s.err }

// Validate runs validators over the current value.
func (s *SelectField) Validate() error {
	s.err = ""
	for _, v := range s.spec.Validators {
		if err := v(s.Value()); err != nil {
			s.err = err.Error()
			return err
		}
	}
	return nil
}
