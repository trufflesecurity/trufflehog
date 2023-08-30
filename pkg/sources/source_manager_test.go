package sources

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
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
	ChunkUnit(ctx context.Context, unit SourceUnit, reporter ChunkReporter) error
	Enumerate(ctx context.Context, reporter UnitReporter) error
}

// Chunk method that writes count bytes to the channel before returning.
type counterChunker struct {
	chunkCounter byte
	count        int
}

func (c *counterChunker) Chunks(ctx context.Context, ch chan *Chunk) error {
	for i := 0; i < c.count; i++ {
		select {
		case ch <- &Chunk{Data: []byte{c.chunkCounter}}:
			c.chunkCounter++
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

// countChunk implements SourceUnit.
type countChunk byte

func (c countChunk) SourceUnitID() string { return fmt.Sprintf("countChunk(%d)", c) }

func (c *counterChunker) Enumerate(ctx context.Context, reporter UnitReporter) error {
	for i := 0; i < c.count; i++ {
		if err := reporter.UnitOk(ctx, countChunk(byte(i))); err != nil {
			return err
		}
	}
	return nil
}

func (c *counterChunker) ChunkUnit(ctx context.Context, unit SourceUnit, reporter ChunkReporter) error {
	return reporter.ChunkOk(ctx, Chunk{Data: []byte{byte(unit.(countChunk))}})
}

// Chunk method that always returns an error.
type errorChunker struct{ error }

func (c errorChunker) Chunks(context.Context, chan *Chunk) error                  { return c }
func (c errorChunker) Enumerate(context.Context, UnitReporter) error              { return c }
func (c errorChunker) ChunkUnit(context.Context, SourceUnit, ChunkReporter) error { return c }

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
	assert.NoError(t, err)
	for i := 0; i < 3; i++ {
		_, err = mgr.Run(context.Background(), handle)
		assert.NoError(t, err)
		chunk, err := tryRead(mgr.Chunks())
		assert.NoError(t, err)
		assert.Equal(t, []byte{byte(i)}, chunk.Data)
		// The Chunks channel should be empty now.
		_, err = tryRead(mgr.Chunks())
		assert.Error(t, err)
	}
}

func TestSourceManagerWait(t *testing.T) {
	mgr := NewManager()
	handle, err := enrollDummy(mgr, &counterChunker{count: 1})
	assert.NoError(t, err)
	// Asynchronously run the source.
	_, err = mgr.ScheduleRun(context.Background(), handle)
	assert.NoError(t, err)
	// Read the 1 chunk we're expecting so Waiting completes.
	<-mgr.Chunks()
	// Wait for all resources to complete.
	assert.NoError(t, mgr.Wait())
	// Enroll and run should return an error now.
	_, err = enrollDummy(mgr, &counterChunker{count: 1})
	assert.Error(t, err)
	_, err = mgr.ScheduleRun(context.Background(), handle)
	assert.Error(t, err)
}

func TestSourceManagerError(t *testing.T) {
	mgr := NewManager()
	handle, err := enrollDummy(mgr, errorChunker{fmt.Errorf("oops")})
	assert.NoError(t, err)
	// A synchronous run should fail.
	_, err = mgr.Run(context.Background(), handle)
	assert.Error(t, err)
	// Scheduling a run should not fail, but the error should surface in
	// Wait().
	ref, err := mgr.ScheduleRun(context.Background(), handle)
	assert.NoError(t, err)
	assert.Error(t, mgr.Wait())
	assert.Error(t, ref.Snapshot().FatalError())
}

func TestSourceManagerReport(t *testing.T) {
	for _, opts := range [][]func(*SourceManager){
		{WithBufferedOutput(8)},
		{WithBufferedOutput(8), WithSourceUnits()},
		{WithBufferedOutput(8), WithSourceUnits(), WithConcurrentUnits(1)},
	} {
		mgr := NewManager(opts...)
		handle, err := enrollDummy(mgr, &counterChunker{count: 4})
		assert.NoError(t, err)
		// Synchronously run the source.
		ref, err := mgr.Run(context.Background(), handle)
		assert.NoError(t, err)
		assert.Equal(t, 0, len(ref.Snapshot().Errors))
		assert.Equal(t, uint64(4), ref.Snapshot().TotalChunks)
	}
}

type unitChunk struct {
	unit   string
	output string
	err    string
}

type unitChunker struct{ steps []unitChunk }

func (c *unitChunker) Chunks(ctx context.Context, ch chan *Chunk) error {
	for _, step := range c.steps {
		if step.err != "" {
			continue
		}
		if err := common.CancellableWrite(ctx, ch, &Chunk{Data: []byte(step.output)}); err != nil {
			return err
		}
	}
	return nil
}
func (c *unitChunker) Enumerate(ctx context.Context, rep UnitReporter) error {
	for _, step := range c.steps {
		if err := rep.UnitOk(ctx, CommonSourceUnit{step.unit}); err != nil {
			return err
		}
	}
	return nil
}
func (c *unitChunker) ChunkUnit(ctx context.Context, unit SourceUnit, rep ChunkReporter) error {
	for _, step := range c.steps {
		if unit.SourceUnitID() != step.unit {
			continue
		}
		if step.err != "" {
			if err := rep.ChunkErr(ctx, fmt.Errorf(step.err)); err != nil {
				return err
			}
			continue
		}
		if err := rep.ChunkOk(ctx, Chunk{Data: []byte(step.output)}); err != nil {
			return err
		}
	}
	return nil
}

func TestSourceManagerNonFatalError(t *testing.T) {
	input := []unitChunk{
		{unit: "one", output: "bar"},
		{unit: "two", err: "oh no"},
		{unit: "three", err: "not again"},
	}
	mgr := NewManager(WithBufferedOutput(8), WithSourceUnits())
	handle, err := enrollDummy(mgr, &unitChunker{input})
	assert.NoError(t, err)
	ref, err := mgr.Run(context.Background(), handle)
	assert.NoError(t, err)
	report := ref.Snapshot()
	assert.Equal(t, len(input), int(report.TotalUnits))
	assert.Equal(t, len(input), int(report.FinishedUnits))
	assert.Equal(t, 1, int(report.TotalChunks))
	assert.Equal(t, 2, len(report.Errors))
	assert.True(t, report.DoneEnumerating)
}

func TestSourceManagerContextCancelled(t *testing.T) {
	mgr := NewManager(WithBufferedOutput(8))
	handle, err := enrollDummy(mgr, &counterChunker{count: 100})
	assert.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	ref, err := mgr.ScheduleRun(ctx, handle)
	assert.NoError(t, err)

	cancel()
	<-ref.Done()
	report := ref.Snapshot()
	assert.Error(t, report.FatalError())
}

type DummyAPI struct {
	registerSource func(context.Context, string, sourcespb.SourceType) (int64, error)
	getJobID       func(context.Context, int64) (int64, error)
}

func (api DummyAPI) RegisterSource(ctx context.Context, name string, kind sourcespb.SourceType) (int64, error) {
	return api.registerSource(ctx, name, kind)
}

func (api DummyAPI) GetJobID(ctx context.Context, id int64) (int64, error) {
	return api.getJobID(ctx, id)
}

func TestSourceManagerJobAndSourceIDs(t *testing.T) {
	mgr := NewManager(WithAPI(DummyAPI{
		registerSource: func(context.Context, string, sourcespb.SourceType) (int64, error) {
			return 1337, nil
		},
		getJobID: func(context.Context, int64) (int64, error) {
			return 9001, nil
		},
	}))
	var (
		initializedJobID    int64
		initializedSourceID int64
	)
	handle, err := mgr.Enroll(context.Background(), "dummy", 1337,
		func(ctx context.Context, jobID, sourceID int64) (Source, error) {
			initializedJobID = jobID
			initializedSourceID = sourceID
			return nil, fmt.Errorf("ignore")
		})
	assert.NoError(t, err)

	ref, _ := mgr.Run(context.Background(), handle)
	assert.Equal(t, int64(1337), initializedSourceID)
	assert.Equal(t, int64(1337), ref.SourceID)
	assert.Equal(t, int64(9001), initializedJobID)
	assert.Equal(t, int64(9001), ref.JobID)
	assert.Equal(t, "dummy", ref.SourceName)
}

// Chunk method that has a custom callback for the Chunks method.
type callbackChunker struct {
	cb func(context.Context, chan *Chunk) error
}

func (c callbackChunker) Chunks(ctx context.Context, ch chan *Chunk) error           { return c.cb(ctx, ch) }
func (c callbackChunker) Enumerate(context.Context, UnitReporter) error              { return nil }
func (c callbackChunker) ChunkUnit(context.Context, SourceUnit, ChunkReporter) error { return nil }

func TestSourceManagerCancelRun(t *testing.T) {
	mgr := NewManager(WithBufferedOutput(8))
	var returnedErr error
	handle, err := enrollDummy(mgr, callbackChunker{func(ctx context.Context, _ chan *Chunk) error {
		// The context passed to Chunks should get cancelled when ref.CancelRun() is called.
		<-ctx.Done()
		returnedErr = fmt.Errorf("oh no: %w", ctx.Err())
		return returnedErr
	}})
	assert.NoError(t, err)

	ref, err := mgr.ScheduleRun(context.Background(), handle)
	assert.NoError(t, err)

	cancelErr := fmt.Errorf("abort! abort!")
	ref.CancelRun(cancelErr)
	<-ref.Done()
	assert.Error(t, ref.Snapshot().FatalError())
	assert.True(t, errors.Is(ref.Snapshot().FatalError(), returnedErr))
	assert.True(t, errors.Is(ref.Snapshot().FatalErrors(), cancelErr))
}

func TestSourceManagerAvailableCapacity(t *testing.T) {
	mgr := NewManager(WithConcurrentSources(1337))
	start, end := make(chan struct{}), make(chan struct{})
	handle, err := enrollDummy(mgr, callbackChunker{func(context.Context, chan *Chunk) error {
		start <- struct{}{} // Send start signal.
		<-end               // Wait for end signal.
		return nil
	}})
	assert.NoError(t, err)

	assert.Equal(t, 1337, mgr.AvailableCapacity())
	ref, err := mgr.ScheduleRun(context.Background(), handle)
	assert.NoError(t, err)

	<-start // Wait for start signal.
	assert.Equal(t, 1336, mgr.AvailableCapacity())
	end <- struct{}{} // Send end signal.
	<-ref.Done()      // Wait for the job to finish.
	assert.Equal(t, 1337, mgr.AvailableCapacity())
}
