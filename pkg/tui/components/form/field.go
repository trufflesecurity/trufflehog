package form

import tea "github.com/charmbracelet/bubbletea"

// Field is the common interface every form widget implements.
//
// The form container drives focus and validation through this interface; the
// concrete widget types (TextField, CheckboxField, SelectField) deal with
// rendering and key handling internally.
type Field interface {
	Spec() FieldSpec
	Value() string
	SetValue(string)
	Focus() tea.Cmd
	Blur()
	Focused() bool
	Update(tea.Msg) (Field, tea.Cmd)
	View() string
	Error() string
	// Validate runs the spec's Validators in order, stores the first error
	// on the field, and returns it.
	Validate() error
}

// newField builds the appropriate widget for a FieldSpec.Kind.
func newField(spec FieldSpec) Field {
	switch spec.Kind {
	case KindCheckbox:
		return NewCheckboxField(spec)
	case KindSelect:
		return NewSelectField(spec)
	case KindSecret:
		return NewSecretField(spec)
	default:
		return NewTextField(spec)
	}
}
