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
	// TotalChunkSize is the total size of a chunk with peek data.
	TotalChunkSize = ChunkSize + PeekSize
)

// Chunker takes a chunk and splits it into chunks of ChunkSize.
func Chunker(originalChunk *Chunk) chan *Chunk {
	chunkChan := make(chan *Chunk)
	go func() {
		defer close(chunkChan)
		if len(originalChunk.Data) <= TotalChunkSize {
			chunkChan <- originalChunk
			return
		}
		r := bytes.NewReader(originalChunk.Data)
		reader := bufio.NewReaderSize(bufio.NewReader(r), ChunkSize)
		for {
			chunkBytes := make([]byte, TotalChunkSize)
			chunk := *originalChunk
			chunkBytes = chunkBytes[:ChunkSize]
			n, err := reader.Read(chunkBytes)
			if err != nil && !errors.Is(err, io.EOF) {
				break
			}
			if n == 0 {
				if errors.Is(err, io.EOF) {
					break
				}
				continue
			}
			peekData, _ := reader.Peek(PeekSize)
			copy(chunkBytes[n:], peekData)
			chunk.Data = chunkBytes[:n+len(peekData)]

			chunkChan <- &chunk
		}
	}()
	return chunkChan
}
