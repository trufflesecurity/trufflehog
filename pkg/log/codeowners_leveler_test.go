package log

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"
)

// testCodeOwner is a test implementation of the codeOwnerData interface.
type testCodeOwner struct {
	owners   []string
	ownersOf func(string) []string
}

func (t testCodeOwner) Owners() []string { return t.owners }
func (t testCodeOwner) OwnersOf(path string) []string {
	if t.ownersOf != nil {
		return t.ownersOf(path)
	}
	return nil
}

func TestCodeOwnersLeveler_Logging(t *testing.T) {
	var buf bytes.Buffer
	lvl := NewCodeOwnersLeveler(testCodeOwner{
		owners: []string{"me", "you"},
		ownersOf: func(path string) []string {
			base := filepath.Base(path)
			// Anonymous functions within a function are of the
			// form: pkg.Function.funcN
			if strings.Count(base, ".") == 2 {
				return []string{"you"}
			}
			return []string{"me"}
		},
	})
	logger, flush := New(
		"service-name",
		WithConsoleSink(&buf, WithLeveler(lvl)),
	)

	lvl.SetLevelFor("me", 1)
	lvl.SetLevelFor("you", 2)

	// "me" codeowner (level 1)
	logger.V(0).Info("line 1")
	logger.V(1).Info("line 2")
	logger.V(2).Info("line 3")
	logger.V(3).Info("line 4")
	func() {
		// "you" codeowner (level 2)
		logger.V(0).Info("line 5")
		logger.V(1).Info("line 6")
		logger.V(2).Info("line 7")
		logger.V(3).Info("line 8")

	}()
	require.Nil(t, flush())

	// buf should have lines 1, 2 (from "me") and 5, 6, 7 (from "you").
	require.Contains(t, buf.String(), "line 1")
	require.Contains(t, buf.String(), "line 2")
	require.NotContains(t, buf.String(), "line 3")
	require.NotContains(t, buf.String(), "line 4")
	require.Contains(t, buf.String(), "line 5")
	require.Contains(t, buf.String(), "line 6")
	require.Contains(t, buf.String(), "line 7")
	require.NotContains(t, buf.String(), "line 8")
}

func TestCodeOwnersLeveler_MostVerboseLevel(t *testing.T) {
	lvl := NewCodeOwnersLeveler(testCodeOwner{
		owners: []string{"me", "you"},
		ownersOf: func(path string) []string {
			return []string{"me", "you"}
		},
	})

	lvl.SetLevelFor("me", 1)
	require.Equal(t, zapcore.Level(-1), lvl.Level())

	lvl.SetLevelFor("you", 2)
	require.Equal(t, zapcore.Level(-2), lvl.Level())
}

func TestCodeOwnersLeveler_AnyEnabled(t *testing.T) {
	lvl := NewCodeOwnersLeveler(testCodeOwner{
		owners: []string{"me", "you"},
		ownersOf: func(path string) []string {
			return []string{"me", "you"}
		},
	})

	lvl.SetLevelFor("me", 1)
	require.True(t, lvl.Enabled(zapcore.Level(0)))
	require.True(t, lvl.Enabled(zapcore.Level(-1)))
	require.False(t, lvl.Enabled(zapcore.Level(-2)))
	require.False(t, lvl.Enabled(zapcore.Level(-3)))

	lvl.SetLevelFor("you", 2)
	require.True(t, lvl.Enabled(zapcore.Level(0)))
	require.True(t, lvl.Enabled(zapcore.Level(-1)))
	require.True(t, lvl.Enabled(zapcore.Level(-2)))
	require.False(t, lvl.Enabled(zapcore.Level(-3)))
}

func TestCodeOwnersLeveler_BaseLevelEnabled(t *testing.T) {
	lvl := NewCodeOwnersLeveler(testCodeOwner{})

	require.True(t, lvl.Enabled(zapcore.Level(0)))
	require.False(t, lvl.Enabled(zapcore.Level(-1)))
	require.False(t, lvl.Enabled(zapcore.Level(-2)))

	lvl.SetLevel(zapcore.Level(-1))
	require.True(t, lvl.Enabled(zapcore.Level(0)))
	require.True(t, lvl.Enabled(zapcore.Level(-1)))
	require.False(t, lvl.Enabled(zapcore.Level(-2)))
}

func TestCodeOwnersLeveler_BaseLevelMostVerbose(t *testing.T) {
	lvl := NewCodeOwnersLeveler(testCodeOwner{
		owners: []string{"me", "you"},
		ownersOf: func(path string) []string {
			return []string{"me", "you"}
		},
	})
	lvl.SetLevelFor("me", 1)
	lvl.SetLevelFor("you", 2)
	SetLevelForControl(lvl, 3)

	require.True(t, lvl.Enabled(zapcore.Level(0)))
	require.True(t, lvl.Enabled(zapcore.Level(-1)))
	require.True(t, lvl.Enabled(zapcore.Level(-2)))
	require.True(t, lvl.Enabled(zapcore.Level(-3)))
	require.False(t, lvl.Enabled(zapcore.Level(-4)))
}
