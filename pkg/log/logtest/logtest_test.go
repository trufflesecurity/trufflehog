package logtest

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDebugContext(t *testing.T) {
	ctx, logs := DebugContext()

	ctx.Logger().V(5).Info("debug line", "key", "value")

	entries := logs.FilterMessage("debug line").All()
	if assert.Len(t, entries, 1) {
		assert.Equal(t, "value", entries[0].ContextMap()["key"])
	}
}
