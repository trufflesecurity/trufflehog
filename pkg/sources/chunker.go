package sources

import (
	"bufio"
	"bytes"
	"errors"
	"io"

	"github.com/sirupsen/logrus"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
)

// Chunker takes a chunk and splits it into chunks of common.ChunkSize.
func Chunker(originalChunk *Chunk) chan *Chunk {
	chunkChan := make(chan *Chunk)
	go func() {
		defer close(chunkChan)
		if len(originalChunk.Data) <= common.ChunkSize+common.PeekSize {
			chunkChan <- originalChunk
			return
		}
		r := bytes.NewReader(originalChunk.Data)
		reader := bufio.NewReaderSize(bufio.NewReader(r), common.ChunkSize)
		for {
			chunkBytes := make([]byte, common.ChunkSize)
			chunk := *originalChunk
			n, err := reader.Read(chunkBytes)
			if err != nil && !errors.Is(err, io.EOF) {
				logrus.WithError(err).Error("Error chunking reader.")
				break
			}
			peekData, _ := reader.Peek(common.PeekSize)
			chunk.Data = append(chunkBytes[:n], peekData...)
			chunkChan <- &chunk
			if errors.Is(err, io.EOF) {
				break
			}
		}
	}()
	return chunkChan
}
