package handlers

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

func TestHandleNonArchiveFile(t *testing.T) {
	file, err := os.Open("testdata/nonarchive.txt")
	assert.Nil(t, err)
	defer file.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	rdr, err := newFileReader(ctx, file)
	assert.NoError(t, err)
	defer rdr.Close()

	handler := newDefaultHandler(defaultHandlerType)
	dataOrErrChan := handler.HandleFile(context.AddLogger(ctx), rdr)
	assert.NoError(t, err)

	wantChunkCount := 6
	count := 0
	for range dataOrErrChan {
		count++
	}

	assert.Equal(t, wantChunkCount, count)
}

// TestHandleFileLineNumbers verifies that line numbers are correctly tracked
// across multiple chunks when processing filesystem files.
// This is a regression test for https://github.com/trufflesecurity/trufflehog/issues/1876
func TestHandleFileLineNumbers(t *testing.T) {
	t.Run("single chunk starts at line 1", func(t *testing.T) {
		// Create a mock chunk reader with one chunk containing 3 lines.
		chunks := []sources.ChunkResult{
			sources.NewChunkResult([]byte("line1\nline2\nline3\n"), 18),
		}

		handler := newDefaultHandler(defaultHandlerType, withChunkReader(mockChunkReader(chunks)))
		reader, err := newFileReader(context.Background(), strings.NewReader("ignored"))
		require.NoError(t, err)

		var results []DataOrErr
		for dataOrErr := range handler.HandleFile(context.Background(), reader) {
			results = append(results, dataOrErr)
		}

		require.Len(t, results, 1)
		assert.Equal(t, int64(1), results[0].LineNumber, "first chunk should start at line 1")
	})

	t.Run("multiple chunks track line numbers correctly", func(t *testing.T) {
		// Create mock chunks with known newline counts.
		// Chunk 1: 10 lines (contentSize covers all data)
		// Chunk 2: 5 lines
		// Chunk 3: 3 lines
		chunk1Data := []byte(strings.Repeat("line\n", 10)) // 10 newlines
		chunk2Data := []byte(strings.Repeat("line\n", 5))  // 5 newlines
		chunk3Data := []byte(strings.Repeat("line\n", 3))  // 3 newlines

		chunks := []sources.ChunkResult{
			sources.NewChunkResult(chunk1Data, len(chunk1Data)),
			sources.NewChunkResult(chunk2Data, len(chunk2Data)),
			sources.NewChunkResult(chunk3Data, len(chunk3Data)),
		}

		handler := newDefaultHandler(defaultHandlerType, withChunkReader(mockChunkReader(chunks)))
		reader, err := newFileReader(context.Background(), strings.NewReader("ignored"))
		require.NoError(t, err)

		var results []DataOrErr
		for dataOrErr := range handler.HandleFile(context.Background(), reader) {
			results = append(results, dataOrErr)
		}

		require.Len(t, results, 3)
		assert.Equal(t, int64(1), results[0].LineNumber, "chunk 1 should start at line 1")
		assert.Equal(t, int64(11), results[1].LineNumber, "chunk 2 should start at line 11 (1 + 10)")
		assert.Equal(t, int64(16), results[2].LineNumber, "chunk 3 should start at line 16 (11 + 5)")
	})

	t.Run("contentSize excludes peek data from line counting", func(t *testing.T) {
		// Simulate peek overlap: chunk has 15 lines total but only 10 are content.
		// The remaining 5 are "peek" data that shouldn't be counted.
		fullData := []byte(strings.Repeat("line\n", 15))         // 15 newlines in data
		contentSize := len([]byte(strings.Repeat("line\n", 10))) // Only 10 are content

		chunks := []sources.ChunkResult{
			sources.NewChunkResult(fullData, contentSize),
			sources.NewChunkResult([]byte("final\n"), 6),
		}

		handler := newDefaultHandler(defaultHandlerType, withChunkReader(mockChunkReader(chunks)))
		reader, err := newFileReader(context.Background(), strings.NewReader("ignored"))
		require.NoError(t, err)

		var results []DataOrErr
		for dataOrErr := range handler.HandleFile(context.Background(), reader) {
			results = append(results, dataOrErr)
		}

		require.Len(t, results, 2)
		assert.Equal(t, int64(1), results[0].LineNumber)
		// Second chunk should start at line 11 (only 10 lines counted from first chunk's content)
		assert.Equal(t, int64(11), results[1].LineNumber, "peek data should not be counted")
	})
}
