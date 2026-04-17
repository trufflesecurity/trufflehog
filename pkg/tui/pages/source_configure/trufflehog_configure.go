package source_configure

import (
	"runtime"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/components/form"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/sources"
)

// trufflehogAdapter wraps the TruffleHog-wide flags form. It doesn't have a
// subcommand of its own; its Cmd() is just the flag tokens that get appended
// to whatever the source adapter emits.
type trufflehogAdapter struct {
	form *form.Form
}

// GetTrufflehogConfiguration builds the TruffleHog-wide flags form.
//
// Booleans are rendered as checkboxes (no more typing "true"/"false"):
// --json, --no-verification, and --only-verified (which expands to
// --results=verified to match the pre-checkbox behavior).
func GetTrufflehogConfiguration() sources.CmdModel {
	specs := []form.FieldSpec{
		{
			Key:   "json",
			Label: "JSON output",
			Help:  "Output results to JSON",
			Kind:  form.KindCheckbox,
			Emit:  form.EmitPresence,
		},
		{
			Key:   "no-verification",
			Label: "Skip Verification",
			Help:  "Check if a suspected secret is real or not",
			Kind:  form.KindCheckbox,
			Emit:  form.EmitPresence,
		},
		{
			Key:      "only-verified",
			Label:    "Verified results only",
			Help:     "Return only verified results",
			Kind:     form.KindCheckbox,
			Emit:     form.EmitConstant,
			Constant: []string{"--results=verified"},
		},
		{
			Key:         "exclude-detectors",
			Label:       "Exclude detectors",
			Help:        "Comma separated list of detector types to exclude. Protobuf name or IDs may be used, as well as ranges. IDs defined here take precedence over the include list.",
			Kind:        form.KindText,
			Emit:        form.EmitLongFlagEq,
			Transform:   stripSpaces,
		},
		{
			Key:         "concurrency",
			Label:       "Concurrency",
			Help:        "Number of concurrent workers.",
			Kind:        form.KindText,
			Placeholder: strconv.Itoa(runtime.NumCPU()),
			Emit:        form.EmitLongFlagEq,
			Validators:  []form.Validate{form.Integer(1, 1<<20)},
		},
	}
	return &trufflehogAdapter{form: form.New(specs)}
}

func stripSpaces(v string) string {
	return strings.ReplaceAll(v, " ", "")
}

func (a *trufflehogAdapter) Init() tea.Cmd { return nil }

func (a *trufflehogAdapter) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	f, cmd := a.form.Update(msg)
	a.form = f
	return a, cmd
}

func (a *trufflehogAdapter) View() string { return a.form.View() }

func (a *trufflehogAdapter) Cmd() []string { return a.form.Args() }

// Summary renders the non-empty field values; "Running with defaults" when
// nothing is set, matching the prior UX.
func (a *trufflehogAdapter) Summary() string {
	s := a.form.Summary()
	if strings.TrimSpace(s) == "" {
		return "\tRunning with defaults\n\n"
	}
	return s + "\n"
}
