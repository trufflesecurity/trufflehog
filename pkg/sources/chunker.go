package sources

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"sync"

	"github.com/sirupsen/logrus"
)

const (
	// ChunkSize is the maximum size of a chunk.
	ChunkSize = 10 * 1024
	// PeekSize is the size of the peek into the previous chunk.
	PeekSize = 3 * 1024
)

var chunkBytesPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, ChunkSize)
	},
}

// Chunker takes a chunk and splits it into chunks of ChunkSize.
func Chunker(originalChunk *Chunk) chan *Chunk {
	chunkChan := make(chan *Chunk)
	go func() {
		defer close(chunkChan)
		if len(originalChunk.Data) <= ChunkSize+PeekSize {
			chunkChan <- originalChunk
			return
		}
		reader := bufio.NewReaderSize(bytes.NewReader(originalChunk.Data), ChunkSize)
		for {
			chunkBytes := chunkBytesPool.Get().([]byte)
			defer chunkBytesPool.Put(chunkBytes)
			n, err := reader.Read(chunkBytes)
			if n == 0 || errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				logrus.WithError(err).Error("Error chunking reader.")
				break
			}
			peekData, _ := reader.Peek(PeekSize)
			chunk := *originalChunk
			chunk.Data = append(chunkBytes[:n], peekData...)
			chunkChan <- &chunk
		}
	}()
	return chunkChan
}
