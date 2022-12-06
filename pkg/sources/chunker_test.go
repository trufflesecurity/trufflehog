package sources

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"testing"

	diskbufferreader "github.com/bill-rich/disk-buffer-reader"
)

func TestChunker(t *testing.T) {
	byteBuffer := bytes.NewBuffer(make([]byte, ChunkSize*9))
	reReader, err := diskbufferreader.New(byteBuffer)
	if err != nil {
		t.Fatal(err)
	}
	defer reReader.Close()

	baseChunkCount := 0

	// Count chunks from looping using chunk size.
	for {
		tmpChunk := make([]byte, ChunkSize)
		_, err := reReader.Read(tmpChunk)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			t.Fatal(err)
		}
		baseChunkCount++
	}
	_ = reReader.Reset()

	// Get the first two chunks for comparing later.
	baseChunkOne := make([]byte, ChunkSize)
	baseChunkTwo := make([]byte, ChunkSize)

	baseReader := bufio.NewReaderSize(reReader, ChunkSize)
	_, _ = baseReader.Read(baseChunkOne)
	peek, _ := baseReader.Peek(PeekSize)
	baseChunkOne = append(baseChunkOne, peek...)
	_, _ = baseReader.Read(baseChunkTwo)
	peek, _ = baseReader.Peek(PeekSize)
	baseChunkTwo = append(baseChunkTwo, peek...)

	// Reset the reader to the beginning and use ChunkReader.
	_ = reReader.Reset()

	testChunkCount := 0
	chunkData, _ := io.ReadAll(reReader)
	originalChunk := &Chunk{
		Data: chunkData,
	}
	for chunk := range Chunker(originalChunk) {
		testChunkCount++
		switch testChunkCount {
		case 1:
			if !bytes.Equal(baseChunkOne, chunk.Data) {
				t.Errorf("First chunk did not match expected. Got: %d bytes, expected: %d bytes", len(chunk.Data), len(baseChunkOne))
			}
		case 2:
			if !bytes.Equal(baseChunkTwo, chunk.Data) {
				t.Errorf("Second chunk did not match expected. Got: %d bytes, expected: %d bytes", len(chunk.Data), len(baseChunkTwo))
			}
		}
	}
	if testChunkCount != baseChunkCount {
		t.Errorf("Wrong number of chunks received. Got %d, expected: %d.", testChunkCount, baseChunkCount)
	}

}
