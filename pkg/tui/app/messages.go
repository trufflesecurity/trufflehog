package app

import "github.com/trufflesecurity/trufflehog/v3/pkg/analyzer"

// Navigation and lifecycle messages. Pages emit these from their Update
// methods to drive routing; the router is the only place these are handled.

// PushMsg pushes a new page onto the navigation stack. Data is passed to the
// target page's factory as the initial payload (may be nil).
type PushMsg struct {
	ID   PageID
	Data any
}

// PopMsg pops the current page. If the stack is empty after the pop, the app
// exits.
type PopMsg struct{}

// ReplaceMsg pops the current page and pushes a new one atomically. This is
// useful for "move forward and don't let the user come back here" flows
// (e.g. wizard → picker).
type ReplaceMsg struct {
	ID   PageID
	Data any
}

// ExitMsg tells the router to hand Args back to the parent process and quit.
// An Args of nil means "user quit" — main.go will call os.Exit(0) directly.
type ExitMsg struct {
	Args []string
}

// RunAnalyzerMsg tells the router to quit the TUI and hand off to
// analyzer.Run, bypassing kingpin entirely.
type RunAnalyzerMsg struct {
	Type string
	Info analyzer.SecretInfo
}

// ResizeMsg is the router-managed replacement for tea.WindowSizeMsg. The
// router computes the content rectangle (terminal size minus chrome) once
// and passes it to the active page so pages can't drift on their own frame
// math.
type ResizeMsg struct {
	Width  int
	Height int
}
