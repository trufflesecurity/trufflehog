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

// Chunker takes a chunk and splits it into chunks of ChunkSize.
// func Chunker(originalChunk *Chunk) chan *Chunk {
// 	chunkChan := make(chan *Chunk)
// 	go func() {
// 		defer close(chunkChan)
// 		if len(originalChunk.Data) <= ChunkSize+PeekSize {
// 			chunkChan <- originalChunk
// 			return
// 		}
// 		reader := bufio.NewReaderSize(bytes.NewReader(originalChunk.Data), ChunkSize)
// 		chunkBytes := make([]byte, ChunkSize)
// 		for {
// 			n, err := reader.Read(chunkBytes)
// 			if n == 0 || errors.Is(err, io.EOF) {
// 				break
// 			}
// 			if err != nil {
// 				logrus.WithError(err).Error("Error chunking reader.")
// 				break
// 			}
// 			peekData, _ := reader.Peek(PeekSize)
// 			chunk := *originalChunk
// 			chunk.Data = make([]byte, n+PeekSize)
// 			copy(chunk.Data, append(chunkBytes[:n], peekData...))
// 			chunkChan <- &chunk
// 		}
// 	}()
// 	return chunkChan
// }

// func Chunker(originalChunk *Chunk) chan *Chunk {
// 	chunkChan := make(chan *Chunk)
// 	go func() {
// 		defer close(chunkChan)
// 		if len(originalChunk.Data) <= ChunkSize+PeekSize {
// 			chunkChan <- originalChunk
// 			return
// 		}
// 		// r := bytes.NewReader(originalChunk.Data)
// 		// reader := bufio.NewReaderSize(bufio.NewReader(r), ChunkSize)
// 		reader := bufio.NewReaderSize(bytes.NewReader(originalChunk.Data), ChunkSize)
// 		for {
// 			chunkBytes := make([]byte, ChunkSize)
// 			chunk := *originalChunk
// 			n, err := reader.Read(chunkBytes)
// 			if err != nil && !errors.Is(err, io.EOF) {
// 				logrus.WithError(err).Error("Error chunking reader.")
// 				break
// 			}
// 			peekData, _ := reader.Peek(PeekSize)
// 			chunk.Data = append(chunkBytes[:n], peekData...)
// 			if n > 0 {
// 				chunkChan <- &chunk
// 			}
// 			if errors.Is(err, io.EOF) {
// 				break
// 			}
// 		}
// 	}()
// 	return chunkChan
// }

var chunkBytesPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, ChunkSize)
	},
}

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
			chunk := *originalChunk
			n, err := reader.Read(chunkBytes)
			if err != nil && !errors.Is(err, io.EOF) {
				logrus.WithError(err).Error("Error chunking reader.")
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
