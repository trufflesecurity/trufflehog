package log

import (
	"errors"
	"runtime"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// CodeOwnersLeveler is a dynamic leveler based on the codeowners of where the
// log was emitted.
type CodeOwnersLeveler struct {
	codeOwners goCodeOwnerData
	baseLevel  zap.AtomicLevel
	levelers   map[string]zap.AtomicLevel
}

// goCodeOwnerData describes a way to list all the possible code owners and a
// way to lookup the codeowners associated with a Go function path (see
// [runtime.Frame.Function]).
type goCodeOwnerData interface {
	// Owners is the list of all possible owners.
	Owners() []string
	// OwnersOf looks up the list of codeowners according to the Go
	// function path (see [runtime.Frame.Function]).
	OwnersOf(goFuncPath string) []string
}

// NewCodeOwnersLeveler initializes a CodeOwnersLeveler with the provided data
// source.
func NewCodeOwnersLeveler(co goCodeOwnerData) *CodeOwnersLeveler {
	// Write to the map on initialization so all other accesses are
	// read-only (and therefore thread-safe).
	levelers := make(map[string]zap.AtomicLevel)
	for _, owner := range co.Owners() {
		levelers[owner] = zap.NewAtomicLevel()
	}
	return &CodeOwnersLeveler{
		codeOwners: co,
		baseLevel:  zap.NewAtomicLevel(),
		levelers:   levelers,
	}
}

// SetLevel sets the minimum level for logs, regardless of code ownership.
func (c *CodeOwnersLeveler) SetLevel(l zapcore.Level) {
	c.baseLevel.SetLevel(l)
}

// Enabled checks that the level is enabled for the codeowner that this method
// was called from.
func (c *CodeOwnersLeveler) Enabled(l zapcore.Level) bool {
	path := callerGoFuncPath(3)
	return c.anyEnabledForPath(path, l)
}

// Level gets the zapcore.Level based on the codeowner that this method was
// called from.
func (c *CodeOwnersLeveler) Level() zapcore.Level {
	path := callerGoFuncPath(3)
	// We return the minimum level because zap's levels get more verbose as
	// the number gets smaller (see [SetLevelForControl]).
	//
	// This is effectively returning the most verbose log level.
	return c.minLevelForPath(path)
}

// SetLevelFor sets the log level for the provided codeowner. An error is
// returned if the codeowner does not exist.
func (c *CodeOwnersLeveler) SetLevelFor(owner string, level int8) error {
	l, ok := c.levelers[owner]
	if !ok {
		return errors.New("no such owner")
	}
	SetLevelForControl(l, level)
	return nil
}

// anyEnabledForPath checks if any of the codeowners for the provided path are
// enabled at the provided level.
func (c *CodeOwnersLeveler) anyEnabledForPath(path string, level zapcore.Level) bool {
	owners := c.codeOwners.OwnersOf(path)
	// If any CODEOWNER is enabled, return true.
	for _, owner := range owners {
		leveler, ok := c.levelers[owner]
		if !ok {
			continue
		}
		if leveler.Enabled(level) {
			return true
		}
	}
	// Default to baseLevel.
	return c.baseLevel.Enabled(level)
}

// minLevelForPath gets the minimum (aka most verbose) level for the provided
// codeowner path.
func (c *CodeOwnersLeveler) minLevelForPath(path string) zapcore.Level {
	owners := c.codeOwners.OwnersOf(path)
	minLevel := c.baseLevel.Level()
	for _, owner := range owners {
		leveler, ok := c.levelers[owner]
		if !ok {
			continue
		}
		minLevel = min(minLevel, leveler.Level())
	}
	return minLevel
}

// callerGoFuncPath gets the non-logging related caller function path and name
// (see [runtime.Frame.Function]).
func callerGoFuncPath(skip int) string {
	pcs := make([]uintptr, 8)
	n := runtime.Callers(skip, pcs)
	frames := runtime.CallersFrames(pcs[:n])

	for {
		f, more := frames.Next()
		if !strings.Contains(f.File, "go.uber.org/zap") && !strings.Contains(f.File, "go-logr") {
			return f.Function
		}
		if !more {
			break
		}
	}
	return ""
}
