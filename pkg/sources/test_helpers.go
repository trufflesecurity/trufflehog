package sources

import (
	"errors"
	"fmt"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

type ChunkFunc func(chunk *Chunk) error

var MatchError = errors.New("chunk doesn't match")

func HandleTestChannel(chunksCh chan *Chunk, cf ChunkFunc) error {
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
		case <-time.After(10 * time.Second):
			return fmt.Errorf("no new chunks received after 10 seconds")
		}
	}
}

type TestReporter struct {
	Units     []SourceUnit
	UnitErrs  []error
	Chunks    []Chunk
	ChunkErrs []error
}

func (t *TestReporter) UnitOk(_ context.Context, unit SourceUnit) error {
	t.Units = append(t.Units, unit)
	return nil
}
func (t *TestReporter) UnitErr(_ context.Context, err error) error {
	t.UnitErrs = append(t.UnitErrs, err)
	return nil
}
func (t *TestReporter) ChunkOk(_ context.Context, chunk Chunk) error {
	t.Chunks = append(t.Chunks, chunk)
	return nil
}
func (t *TestReporter) ChunkErr(_ context.Context, err error) error {
	t.ChunkErrs = append(t.ChunkErrs, err)
	return nil
}
