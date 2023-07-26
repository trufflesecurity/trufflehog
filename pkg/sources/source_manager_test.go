package sources

import (
	"fmt"
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"google.golang.org/protobuf/types/known/anypb"
)

// DummySource implements Source and is used for testing a SourceManager.
type DummySource struct {
	sourceID int64
	jobID    int64
	chunker
}

func (d *DummySource) Type() sourcespb.SourceType { return 1337 }
func (d *DummySource) SourceID() int64            { return d.sourceID }
func (d *DummySource) JobID() int64               { return d.jobID }
func (d *DummySource) Init(_ context.Context, _ string, jobID, sourceID int64, _ bool, _ *anypb.Any, _ int) error {
	d.sourceID = sourceID
	d.jobID = jobID
	return nil
}
func (d *DummySource) GetProgress() *Progress { return nil }

// Interface to easily test different chunking methods.
type chunker interface {
	Chunks(context.Context, chan *Chunk) error
}

// Chunk method that writes count bytes to the channel before returning.
type counterChunker struct {
	chunkCounter byte
	count        int
}

func (c *counterChunker) Chunks(_ context.Context, ch chan *Chunk) error {
	for i := 0; i < c.count; i++ {
		ch <- &Chunk{Data: []byte{c.chunkCounter}}
		c.chunkCounter++
	}
	return nil
}

// enrollDummy is a helper function to enroll a DummySource with a SourceManager.
func enrollDummy(mgr *SourceManager, chunkMethod chunker) (handle, error) {
	return mgr.Enroll(context.Background(), "dummy", 1337,
		func(ctx context.Context, jobID, sourceID int64) (Source, error) {
			source := &DummySource{chunker: chunkMethod}
			if err := source.Init(ctx, "dummy", jobID, sourceID, true, nil, 42); err != nil {
				return nil, err
			}
			return source, nil
		})
}

// tryRead is a helper function that will try to read from a channel and return
// an error if it cannot.
func tryRead(ch <-chan *Chunk) (*Chunk, error) {
	select {
	case chunk := <-ch:
		return chunk, nil
	default:
		return nil, fmt.Errorf("no chunk available")
	}
}

func TestSourceManagerRun(t *testing.T) {
	mgr := NewManager(WithBufferedOutput(8))
	handle, err := enrollDummy(mgr, &counterChunker{count: 1})
	if err != nil {
		t.Fatalf("unexpected error enrolling source: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := mgr.Run(context.Background(), handle); err != nil {
			t.Fatalf("unexpected error running source: %v", err)
		}
		chunk, err := tryRead(mgr.Chunks())
		if err != nil {
			t.Fatalf("reading chunk failed: %v", err)
		}
		if chunk.Data[0] != byte(i) {
			t.Fatalf("unexpected chunk value, wanted %v, got: %v", chunk.Data[0], i)
		}

		// The Chunks channel should be empty now.
		if chunk, err := tryRead(mgr.Chunks()); err == nil {
			t.Fatalf("unexpected chunk found: %+v", chunk)
		}
	}
}

func TestSourceManagerWait(t *testing.T) {
	mgr := NewManager()
	handle, err := enrollDummy(mgr, &counterChunker{count: 1})
	if err != nil {
		t.Fatalf("unexpected error enrolling source: %v", err)
	}
	// Asynchronously run the source.
	if err := mgr.ScheduleRun(context.Background(), handle); err != nil {
		t.Fatalf("unexpected error scheduling run: %v", err)
	}
	// Read the 1 chunk we're expecting so Waiting completes.
	<-mgr.Chunks()
	// Wait for all resources to complete.
	if err := mgr.Wait(); err != nil {
		t.Fatalf("unexpected error waiting: %v", err)
	}
	// Enroll and run should return an error now.
	if _, err := enrollDummy(mgr, &counterChunker{count: 1}); err == nil {
		t.Fatalf("expected enroll to fail")
	}
	if err := mgr.ScheduleRun(context.Background(), handle); err == nil {
		t.Fatalf("expected scheduling run to fail")
	}
}
