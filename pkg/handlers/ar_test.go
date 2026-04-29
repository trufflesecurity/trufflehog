package handlers

import (
	"context"
	"io"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	trContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

func TestHandleARFile(t *testing.T) {
	file, err := os.Open("testdata/test.deb")
	assert.Nil(t, err)
	defer file.Close()

	ctx, cancel := trContext.WithTimeout(trContext.Background(), 3*time.Second)
	defer cancel()

	rdr, err := newFileReader(ctx, file)
	assert.NoError(t, err)
	defer rdr.Close()

	handler := newARHandler()
	dataOrErrChan := handler.HandleFile(trContext.AddLogger(ctx), rdr)
	assert.NoError(t, err)

	wantChunkCount := 102
	count := 0
	for range dataOrErrChan {
		count++
	}

	assert.Equal(t, wantChunkCount, count)
}

// TestARHandler_NonArchiveErrPreservesIdentity is a regression test for the
// %v wrap on the ErrProcessingWarning send to dataOrErrChan in
// processARFiles' handleNonArchiveContent error path. Before the fix, wrapping
// handleNonArchiveContent's
// return value with %v dropped the inner error's identity from the errors.Is
// chain, causing isFatal in handleChunksWithError to misclassify cancellation
// (and other fatal causes) as a non-fatal warning. The test injects a
// cancelling chunk reader so handleNonArchiveContent's CancellableWrite
// returns context.Canceled, which is then wrapped by processARFiles. It
// asserts both that the outer ErrProcessingWarning wrap is preserved and
// that the inner cancellation cause remains inspectable.
func TestARHandler_NonArchiveErrPreservesIdentity(t *testing.T) {
	file, err := os.Open("testdata/test.deb")
	require.NoError(t, err)
	defer file.Close()

	ctx, cancel := trContext.WithCancel(trContext.Background())
	defer cancel()

	rdr, err := newFileReader(ctx, file)
	require.NoError(t, err)
	defer rdr.Close()

	// Cancel the parent context the moment handleNonArchiveContent asks for
	// chunks, then deliver a single non-error chunk. CancellableWrite of that
	// chunk's data sees the cancelled context and returns context.Canceled,
	// which handleNonArchiveContent returns and processARFiles wraps. This
	// is the only path that exercises the processARFiles dataOrErrChan
	// ErrProcessingWarning wrap.
	cancellingChunkReader := sources.ChunkReader(func(_ trContext.Context, _ io.Reader) <-chan sources.ChunkResult {
		ch := make(chan sources.ChunkResult, 1)
		cancel()
		ch <- sources.NewChunkResult([]byte("data"), 4)
		close(ch)
		return ch
	})

	handler := &arHandler{
		defaultHandler: newDefaultHandler(arHandlerType, withChunkReader(cancellingChunkReader)),
	}

	var got []DataOrErr
	for d := range handler.HandleFile(trContext.AddLogger(ctx), rdr) {
		got = append(got, d)
	}

	var warnErr error
	for _, d := range got {
		if d.Err != nil {
			warnErr = d.Err
			break
		}
	}
	require.Error(t, warnErr, "expected wrapped warning from ar.go non-archive error path")

	assert.ErrorIs(t, warnErr, ErrProcessingWarning,
		"outer ErrProcessingWarning wrap should be preserved")
	assert.ErrorIs(t, warnErr, context.Canceled,
		"inner cancellation cause should be inspectable via errors.Is")
	assert.True(t, isFatal(warnErr),
		"isFatal should classify the wrapped error based on the inner cause")
}
