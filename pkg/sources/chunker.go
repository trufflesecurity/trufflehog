package sources

import (
	"bufio"
	"bytes"
	"errors"
	"io"
)

const (
	// ChunkSize is the maximum size of a chunk.
	ChunkSize = 10 * 1024
	// PeekSize is the size of the peek into the previous chunk.
	PeekSize = 3 * 1024
)

// Chunker takes a chunk and splits it into chunks of ChunkSize.
func Chunker(originalChunk *Chunk) chan *Chunk {
	chunkChan := make(chan *Chunk)
	go func() {
		defer close(chunkChan)
		if len(originalChunk.Data) <= ChunkSize+PeekSize {
			chunkChan <- originalChunk
			return
		}
		r := bytes.NewReader(originalChunk.Data)
		reader := bufio.NewReaderSize(bufio.NewReader(r), ChunkSize)
		for {
			chunkBytes := make([]byte, ChunkSize)
			chunk := *originalChunk
			n, err := reader.Read(chunkBytes)
			if err != nil && !errors.Is(err, io.EOF) {
				break
			}
			peekData, _ := reader.Peek(PeekSize)
			chunk.Data = append(chunkBytes[:n], peekData...)
			if n > 0 {
				chunkChan <- &chunk
			}
			if errors.Is(err, io.EOF) {
				break
			}
		}
	}()
	return chunkChan
}
