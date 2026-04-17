package sources

import (
	tea "github.com/charmbracelet/bubbletea"
)

// CmdModel is the shim contract consumed by source_configure's tab
// components while the page layer still owns sequencing.
//
// Cmd() returns a kingpin arg vector including the Definition.Command
// subcommand token. This replaces the old Cmd() string that
// whitespace-split in pkg/tui/tui.go and broke space-containing values
// like filesystem paths.
type CmdModel interface {
	tea.Model
	Cmd() []string
	Summary() string
}

// GetSourceNotes returns the Definition.Note matching sourceName (by Title).
//
// Kept as a shim while source_configure still dispatches by display name;
// phase 4 migrates the dispatch to IDs and this helper can be deleted.
func GetSourceNotes(sourceName string) string {
	if d, ok := ByTitle(sourceName); ok {
		return d.Note
	}
	return ""
}

// GetSourceFields returns a FormAdapter for the source whose Title matches
// sourceName, or nil if no match. Same shim deal as GetSourceNotes.
func GetSourceFields(sourceName string) CmdModel {
	d, ok := ByTitle(sourceName)
	if !ok {
		return nil
	}
	return NewFormAdapter(d)
}
