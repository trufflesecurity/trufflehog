package logtest

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/log"
)

func TestDebugContext(t *testing.T) {
	ctx, logs := DebugContext()

	ctx.Logger().V(5).Info("debug line", "key", "value")

	entries := logs.FilterMessage("debug line").All()
	if assert.Len(t, entries, 1) {
		assert.Equal(t, "value", entries[0].ContextMap()["key"])
	}
}

// recorder is a testing.TB that records failures instead of failing the test.
type recorder struct {
	testing.TB
	failed bool
}

func (r *recorder) Helper() {}

func (r *recorder) Errorf(string, ...any) { r.failed = true }

func TestSourceContext(t *testing.T) {
	ctx, logs := SourceContext(true)
	ctx.Logger().V(1).Info("init line")
	ctx.Logger().V(5).Info("debug line", "token", "not-a-secret")

	r := &recorder{TB: t}
	CheckInitLine(r, logs.All())
	CheckSourceLines(r, logs.All(), "secret-value")
	assert.False(t, r.failed)

	ctx, logs = SourceContext(false)
	ctx.Logger().V(5).Info("debug line")
	ctx.Logger().Info("info line")
	assert.Equal(t, 1, logs.Len())
}

func TestCheckInitLine(t *testing.T) {
	ctx, logs := SourceContext(true)
	ctx.Logger().V(2).Info("not an init line")

	r := &recorder{TB: t}
	CheckInitLine(r, logs.All())
	assert.True(t, r.failed)
}

func TestCheckSourceLines(t *testing.T) {
	t.Run("missing field", func(t *testing.T) {
		_, logs := SourceContext(true)
		// a logger that did not come from the source's context has no source fields
		other, otherLogs := DebugContext()
		other.Logger().Info("line from another logger")

		r := &recorder{TB: t}
		CheckSourceLines(r, append(logs.All(), otherLogs.All()...))
		assert.True(t, r.failed)
	})

	t.Run("no lines", func(t *testing.T) {
		_, logs := SourceContext(true)

		r := &recorder{TB: t}
		CheckSourceLines(r, logs.All())
		assert.True(t, r.failed)
	})

	t.Run("secret in message", func(t *testing.T) {
		ctx, logs := SourceContext(true)
		ctx.Logger().Info("found secret-value")

		r := &recorder{TB: t}
		CheckSourceLines(r, logs.All(), "secret-value")
		assert.True(t, r.failed)
	})

	t.Run("secret in field", func(t *testing.T) {
		ctx, logs := SourceContext(true)
		ctx.Logger().Info("line", "value", "secret-value")

		r := &recorder{TB: t}
		CheckSourceLines(r, logs.All(), "secret-value")
		assert.True(t, r.failed)
	})
}

func TestCheckNoDebugLines(t *testing.T) {
	// a source that turns on debug by itself leaks debug lines into a normal run
	ctx, logs := SourceContext(false)
	context.WithLogLevel(ctx, log.DebugLevel).Logger().V(5).Info("leaked debug line")
	ctx.Logger().Info("info line")
	require.Equal(t, 2, logs.Len())

	r := &recorder{TB: t}
	CheckNoDebugLines(r, logs.All())
	assert.True(t, r.failed)

	r = &recorder{TB: t}
	CheckNoDebugLines(r, logs.FilterMessage("info line").All())
	assert.False(t, r.failed)
}
