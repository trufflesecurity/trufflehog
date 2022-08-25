package common

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net/http"
	"testing"

	diskbufferreader "github.com/bill-rich/disk-buffer-reader"
)

func TestChunker(t *testing.T) {
	resp, err := http.Get("https://raw.githubusercontent.com/bill-rich/bad-secrets/master/FifteenMB.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	reReader, err := diskbufferreader.New(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	defer reReader.Close()

	baseChunkCount := 0

	// Count chunks from looping using chunk size.
	for {
		baseChunkCount++
		tmpChunk := make([]byte, ChunkSize)
		_, err := reReader.Read(tmpChunk)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			t.Error(err)
		}
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
	for chunk := range ChunkReader(reReader) {
		testChunkCount++
		switch testChunkCount {
		case 1:
			if !bytes.Equal(baseChunkOne, chunk) {
				t.Errorf("First chunk did not match expected. Got: %d bytes, expected: %d bytes", len(chunk), len(baseChunkOne))
			}
		case 2:
			if !bytes.Equal(baseChunkTwo, chunk) {
				t.Errorf("Second chunk did not match expected. Got: %d bytes, expected: %d bytes", len(chunk), len(baseChunkTwo))
			}
		}
	}
	if testChunkCount != baseChunkCount {
		t.Errorf("Wrong number of chunks received. Got %d, expected: %d.", testChunkCount, baseChunkCount)
	}

}
