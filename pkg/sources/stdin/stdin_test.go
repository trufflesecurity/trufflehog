package stdin

import (
	stdctx "context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest/observer"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/handlers"
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

// errReporter records chunk errors, like the source manager does.
type errReporter struct {
	errs []error
}

func (r *errReporter) ChunkOk(context.Context, sources.Chunk) error { return nil }

func (r *errReporter) ChunkErr(_ context.Context, err error) error {
	r.errs = append(r.errs, err)
	return nil
}

// ChunkUnit reports the error from reading stdin as a scan error instead of dropping
// it or failing the whole run.
func TestSource_ChunkUnitReportsReadError(t *testing.T) {
	r, w, err := os.Pipe()
	require.NoError(t, err)
	require.NoError(t, w.Close())
	require.NoError(t, r.Close())
	setStdin(t, r)

	ctx := context.Background()
	s := new(Source)
	require.NoError(t, s.Init(ctx, "test source", 1, 1, false, nil, 1))
	reporter := &errReporter{}
	require.NoError(t, s.ChunkUnit(ctx, sources.CommonSourceUnit{ID: "<stdin>"}, reporter))
	assert.Len(t, reporter.errs, 1)
}

// Input that is still open when --archive-timeout runs out is reported with a hint
// about the flag.
func TestSource_ChunkUnitReportsArchiveTimeout(t *testing.T) {
	handlers.SetArchiveMaxTimeout(100 * time.Millisecond)
	t.Cleanup(func() { handlers.SetArchiveMaxTimeout(60 * time.Second) })

	r, w, err := os.Pipe()
	require.NoError(t, err)
	t.Cleanup(func() { _ = w.Close(); _ = r.Close() })
	// Enough data for the type check, then the pipe stays open like a stream.
	_, err = w.WriteString(strings.Repeat("line of log output\n", 1000))
	require.NoError(t, err)
	setStdin(t, r)

	ctx := context.Background()
	s := new(Source)
	require.NoError(t, s.Init(ctx, "test source", 1, 1, false, nil, 1))
	reporter := &errReporter{}
	require.NoError(t, s.ChunkUnit(ctx, sources.CommonSourceUnit{ID: "<stdin>"}, reporter))
	require.Len(t, reporter.errs, 1)
	assert.ErrorIs(t, reporter.errs[0], stdctx.DeadlineExceeded)
	assert.Contains(t, reporter.errs[0].Error(), "--archive-timeout")
}
