package form

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/theme"
)

// CheckboxField is a boolean toggle rendered as `[ ] Label` / `[x] Label`.
// It replaces the legacy "type true/false" text inputs.
type CheckboxField struct {
	spec    FieldSpec
	checked bool
	focused bool
	err     string
}

// NewCheckboxField constructs a CheckboxField for the given spec.
func NewCheckboxField(spec FieldSpec) *CheckboxField {
	c := &CheckboxField{spec: spec}
	c.checked = isTruthy(spec.Default)
	return c
}

// Spec returns the underlying FieldSpec.
func (c *CheckboxField) Spec() FieldSpec { return c.spec }

// Value returns "true" when checked, "" otherwise.
func (c *CheckboxField) Value() string {
	if c.checked {
		return "true"
	}
	return ""
}

// SetValue accepts any truthy string ("true"/"1"/"yes"/"on") as checked.
func (c *CheckboxField) SetValue(v string) { c.checked = isTruthy(v) }

// Focus marks the checkbox as focused.
func (c *CheckboxField) Focus() tea.Cmd { c.focused = true; return nil }

// Blur removes focus.
func (c *CheckboxField) Blur() { c.focused = false }

// Focused reports whether the checkbox has focus.
func (c *CheckboxField) Focused() bool { return c.focused }

// Update toggles the checkbox on space / x.
func (c *CheckboxField) Update(msg tea.Msg) (Field, tea.Cmd) {
	if !c.focused {
		return c, nil
	}
	if key, ok := msg.(tea.KeyMsg); ok {
		switch key.String() {
		case " ", "x", "space":
			c.checked = !c.checked
		case "y", "Y":
			c.checked = true
		case "n", "N":
			c.checked = false
		}
	}
	return c, nil
}

// View renders `[ ] Label` / `[x] Label`.
func (c *CheckboxField) View() string {
	styles := theme.DefaultStyles()
	box := "[ ]"
	if c.checked {
		box = "[x]"
	}
	label := c.spec.Label
	if label == "" {
		label = c.spec.Key
	}
	line := box + " " + label
	if c.focused {
		line = styles.Primary.Render("❯ " + line)
	} else {
		line = "  " + line
	}
	var b strings.Builder
	b.WriteString(line)
	b.WriteString("\n")
	if c.spec.Help != "" {
		b.WriteString("    " + styles.Hint.Render(c.spec.Help))
		b.WriteString("\n")
	}
	b.WriteString("\n")
	return b.String()
}

// Error returns the most recent validation error.
func (c *CheckboxField) Error() string { return c.err }

// Validate runs validators over the current value.
func (c *CheckboxField) Validate() error {
	c.err = ""
	for _, v := range c.spec.Validators {
		if err := v(c.Value()); err != nil {
			c.err = err.Error()
			return err
		}
	}
	return nil
}
