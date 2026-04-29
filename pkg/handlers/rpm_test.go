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

func TestHandleRPMFile(t *testing.T) {
	file, err := os.Open("testdata/test.rpm")
	assert.Nil(t, err)
	defer file.Close()

	ctx, cancel := trContext.WithTimeout(trContext.Background(), 3*time.Second)
	defer cancel()

	rdr, err := newFileReader(ctx, file)
	assert.NoError(t, err)
	defer rdr.Close()

	handler := newRPMHandler()
	dataOrErrChan := handler.HandleFile(trContext.AddLogger(ctx), rdr)
	assert.NoError(t, err)

	wantChunkCount := 179
	count := 0
	for range dataOrErrChan {
		count++
	}

	assert.Equal(t, wantChunkCount, count)
}

// TestRPMHandler_NonArchiveErrPreservesIdentity is a regression test for the
// %v wrap at rpm.go:120. Same shape as TestARHandler_NonArchiveErrPreservesIdentity:
// inject a cancelling chunk reader so handleNonArchiveContent's CancellableWrite
// returns context.Canceled, which processRPMFiles wraps with ErrProcessingWarning.
// Asserts the outer warning wrap and inner cancellation cause are both
// observable via errors.Is so isFatal can classify correctly.
func TestRPMHandler_NonArchiveErrPreservesIdentity(t *testing.T) {
	file, err := os.Open("testdata/test.rpm")
	require.NoError(t, err)
	defer file.Close()

	ctx, cancel := trContext.WithCancel(trContext.Background())
	defer cancel()

	rdr, err := newFileReader(ctx, file)
	require.NoError(t, err)
	defer rdr.Close()

	cancellingChunkReader := sources.ChunkReader(func(_ trContext.Context, _ io.Reader) <-chan sources.ChunkResult {
		ch := make(chan sources.ChunkResult, 1)
		cancel()
		ch <- sources.NewChunkResult([]byte("data"), 4)
		close(ch)
		return ch
	})

	handler := &rpmHandler{
		defaultHandler: newDefaultHandler(rpmHandlerType, withChunkReader(cancellingChunkReader)),
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
	require.Error(t, warnErr, "expected wrapped warning from rpm.go non-archive error path")

	assert.ErrorIs(t, warnErr, ErrProcessingWarning,
		"outer ErrProcessingWarning wrap should be preserved")
	assert.ErrorIs(t, warnErr, context.Canceled,
		"inner cancellation cause should be inspectable via errors.Is")
	assert.True(t, isFatal(warnErr),
		"isFatal should classify the wrapped error based on the inner cause")
}
