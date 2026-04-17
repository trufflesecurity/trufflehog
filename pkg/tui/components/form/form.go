// Package form is the unified field/validator/widget layer used to collect
// kingpin arguments from the user.
//
// Until phase 2 fills it in with real widgets, this file only declares the
// declarative types sources and pages reach for:
//
//   - FieldSpec — the data-only description of a single input.
//   - FieldKind — text vs checkbox vs select vs secret.
//   - EmitMode  — how a field's value is rendered into a kingpin arg vector.
//   - Validate  — the validator function signature.
//
// The actual TextField / CheckboxField / SelectField widgets and the Form
// container land in phase 2 alongside their unit tests.
package form

// FieldKind identifies how a field is rendered and how its value is
// interpreted when emitting kingpin arguments.
type FieldKind int

const (
	// KindText is a free-text input.
	KindText FieldKind = iota
	// KindCheckbox is a boolean toggle. Replaces typing "true"/"false".
	KindCheckbox
	// KindSelect is a single-select out of a fixed list of options.
	KindSelect
	// KindSecret is a free-text input with redacted rendering.
	KindSecret
)

// EmitMode describes how a FieldSpec's value is rendered into the kingpin
// arg vector returned by Form.Args().
type EmitMode int

const (
	// EmitLongFlag renders as two tokens: ["--key", value].
	EmitLongFlag EmitMode = iota
	// EmitLongFlagEq renders as one token: ["--key=value"].
	EmitLongFlagEq
	// EmitPresence renders as ["--key"] when the value is "true" and
	// nothing otherwise. Used for boolean checkboxes that map to
	// presence-only flags (e.g. --json, --no-verification).
	EmitPresence
	// EmitConstant renders the field's Constant slice verbatim when the
	// value is "true", nothing otherwise. Used for checkboxes that expand
	// to a canned flag like --results=verified.
	EmitConstant
	// EmitPositional renders the value as a single positional argument
	// (no flag name).
	EmitPositional
	// EmitNone is a non-emitting field, e.g. a checkbox that gates another
	// field but doesn't itself contribute an argument.
	EmitNone
)

// SelectOption is one entry in a KindSelect field.
type SelectOption struct {
	Label string
	Value string
}

// Validate runs on field blur and on form submit. A non-nil error is
// rendered next to the field and blocks submission.
type Validate func(value string) error

// FieldSpec declaratively describes one input in a Form. Widget behavior and
// the emitted kingpin tokens are both derived from this struct — sources no
// longer hand-build `command []string`.
type FieldSpec struct {
	// Key is the kingpin flag name without the leading "--"
	// (e.g. "only-verified"). For EmitPositional fields it's used as the
	// summary label only.
	Key string
	// Label is the human-readable label rendered above the input.
	Label string
	// Help is a secondary description shown under the label.
	Help string
	// Kind controls the widget type.
	Kind FieldKind
	// Placeholder is displayed when the field is empty; it is never used
	// as a default value (see the plan's "textinputs placeholder hack"
	// note).
	Placeholder string
	// Default is the pre-populated value used when the form is first
	// opened. Empty string means no default.
	Default string
	// Options populates a KindSelect field.
	Options []SelectOption
	// Validators run in order on blur and on submit. Submission is blocked
	// if any returns a non-nil error.
	Validators []Validate
	// Emit controls how Form.Args() renders this field into tokens.
	Emit EmitMode
	// Constant is the token slice emitted when Emit is EmitConstant and
	// the field value is "true".
	Constant []string
	// Group tags a field for cross-field constraints (e.g. an XOr group
	// shared by several fields that are mutually exclusive).
	Group string
}

// Constraint is a cross-field validator evaluated on submit. Returning a
// non-nil error blocks submission and shows the message above the form.
type Constraint func(values map[string]string) error
