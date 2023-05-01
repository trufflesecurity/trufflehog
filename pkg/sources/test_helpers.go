package sources

import (
	"errors"
	"fmt"
	"time"
)

type ChunkFunc func(chunk *Chunk) error

var MatchError = errors.New("chunk doesn't match")

func HandleTestChannel(chunksCh chan *Chunk, cf ChunkFunc, timeout int) error {
	for {
		select {
		case gotChunk := <-chunksCh:
			err := cf(gotChunk)
			if err != nil {
				if errors.Is(err, MatchError) {
					continue
				}
				return err
			}
			return nil
		case <-time.After(time.Duration(timeout) * time.Second):
			return fmt.Errorf("no new chunks received after %d seconds", timeout)
		}
	}
}
