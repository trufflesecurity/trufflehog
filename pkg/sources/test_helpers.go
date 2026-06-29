package sources

import (
	"errors"
	"fmt"
	"time"
)

type ChunkFunc func(chunk *Chunk) error

// ErrMatch indicates a chunk did not match and the helper should keep waiting.
var ErrMatch = errors.New("chunk doesn't match")

func HandleTestChannel(chunksCh chan *Chunk, cf ChunkFunc) error {
	for {
		select {
		case gotChunk := <-chunksCh:
			err := cf(gotChunk)
			if err != nil {
				if errors.Is(err, ErrMatch) {
					continue
				}
				return err
			}
			return nil
		case <-time.After(10 * time.Second):
			return fmt.Errorf("no new chunks received after 10 seconds")
		}
	}
}
