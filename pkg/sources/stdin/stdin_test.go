package stdin

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest/observer"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/log/logtest"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

// setStdin replaces os.Stdin with r until the test ends. Tests that call it must not
// run in parallel.
func setStdin(t *testing.T, r *os.File) {
	t.Helper()
	orig := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = orig })
}

// pipeStdin makes os.Stdin read data, then end.
func pipeStdin(t *testing.T, data string) {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)
	t.Cleanup(func() { _ = r.Close() })
	go func() {
		_, _ = w.WriteString(data)
		_ = w.Close()
	}()
	setStdin(t, r)
}

func TestSource_DebugLogging(t *testing.T) {
	const testSecret = "stdindebuglogtestsecret"

	runSource := func(t *testing.T, debug bool) []observer.LoggedEntry {
		t.Helper()
		pipeStdin(t, "token = "+testSecret+"\n")
		ctx, logs := logtest.SourceContext(debug)
		s := new(Source)
		require.NoError(t, s.Init(ctx, "test source", 1, 1, false, nil, 1))
		if debug {
			logtest.CheckInitLine(t, logs.All())
		}

		chunksCh := make(chan *sources.Chunk, 10)
		require.NoError(t, s.Chunks(ctx, chunksCh))
		close(chunksCh)
		var data strings.Builder
		for chunk := range chunksCh {
			data.Write(chunk.Data)
		}
		assert.Contains(t, data.String(), testSecret)
		return logs.All()
	}

	t.Run("debug on", func(t *testing.T) {
		logtest.CheckSourceLines(t, runSource(t, true), testSecret)
	})

	t.Run("debug off", func(t *testing.T) {
		logtest.CheckNoDebugLines(t, runSource(t, false))
	})
}

// ChunkUnit returns the error from reading stdin instead of dropping it.
func TestSource_ChunkUnitReturnsReadError(t *testing.T) {
	r, w, err := os.Pipe()
	require.NoError(t, err)
	require.NoError(t, w.Close())
	require.NoError(t, r.Close())
	setStdin(t, r)

	ctx := context.Background()
	s := new(Source)
	require.NoError(t, s.Init(ctx, "test source", 1, 1, false, nil, 1))
	err = s.ChunkUnit(ctx, sources.CommonSourceUnit{ID: "<stdin>"}, sources.ChanReporter{Ch: make(chan *sources.Chunk, 1)})
	assert.Error(t, err)
}
