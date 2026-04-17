package sources

import (
	"fmt"
	"sort"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/components/form"
)

// Tier distinguishes OSS sources (usable directly) from Enterprise sources
// (advertised but gated behind a contact-sales page).
type Tier int

const (
	// TierOSS is a source shipped in the open-source build. The TUI can
	// build a full arg vector and hand it off to kingpin.
	TierOSS Tier = iota
	// TierEnterprise is an advertised-only source; selecting it surfaces
	// the enterprise contact link rather than a form.
	TierEnterprise
)

// Definition is a single source's declarative description.
//
// It replaces the two parallel switches in sources.go (GetSourceFields /
// GetSourceNotes) with an id-keyed registry, and replaces the stringly-typed
// CmdModel.Cmd() pattern with form.FieldSpec + Form.Args().
type Definition struct {
	// ID is the stable, kebab-case identifier (e.g. "github", "gcs").
	ID string
	// Title is the human-readable label shown in the source picker.
	Title string
	// Description is the one-line sub-label shown in the source picker.
	Description string
	// Tier controls whether the source opens a config form or the
	// enterprise contact card.
	Tier Tier
	// Note is an optional informational banner displayed above the form.
	Note string
	// Command is the kingpin subcommand (e.g. "github", "filesystem").
	// Empty for enterprise sources.
	Command string
	// Fields describe the per-source inputs.
	Fields []form.FieldSpec
	// Constraints are cross-field validators evaluated on submit (e.g. an
	// XOr group between mutually-exclusive target selectors).
	Constraints []form.Constraint
	// ExtraArgs are appended verbatim to the emitted arg vector after the
	// form's fields. Used by sources that need a constant flag (e.g. gcs
	// always appending --cloud-environment).
	ExtraArgs []string
	// BuildArgs, when non-nil, replaces the default form.BuildArgs result
	// for this source. Provided for the handful of sources whose
	// arg-emission logic is genuinely not declarative (e.g. elasticsearch's
	// mutex-of-modes, jenkins's auth gating).
	BuildArgs func(values map[string]string) []string
}

// registry is the process-wide source registry. Entries are added at init
// time by each source package.
var registry = map[string]Definition{}

// Register adds a Definition to the process-wide registry. Registering the
// same ID twice panics — this is intentional so accidental duplicates fail
// loudly at startup rather than silently shadowing one another.
func Register(def Definition) {
	if def.ID == "" {
		panic("sources: Definition.ID cannot be empty")
	}
	if _, ok := registry[def.ID]; ok {
		panic(fmt.Sprintf("sources: duplicate Definition %q", def.ID))
	}
	registry[def.ID] = def
}

// Get looks up a Definition by ID. The second return is false if no source
// is registered under that ID.
func Get(id string) (Definition, bool) {
	d, ok := registry[id]
	return d, ok
}

// All returns every registered Definition, alphabetically by Title. The
// result is a copy; mutating it does not affect the registry.
func All() []Definition {
	out := make([]Definition, 0, len(registry))
	for _, d := range registry {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Title < out[j].Title
	})
	return out
}

// ByTitle looks up a Definition by its Title (case-insensitive).
//
// Kept for compatibility with source_select's title-based dispatch; once
// source-picker switches to IDs in phase 4 this helper becomes unused and
// can be removed.
func ByTitle(title string) (Definition, bool) {
	want := strings.ToLower(strings.TrimSpace(title))
	for _, d := range registry {
		if strings.ToLower(d.Title) == want {
			return d, true
		}
	}
	return Definition{}, false
}
