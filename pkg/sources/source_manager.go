package sources

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
)

type SourceManager struct {
	api   apiClient
	hooks []JobProgressHook
	// Pool limiting the amount of concurrent sources running.
	pool                errgroup.Group
	poolLimit           int
	currentRunningCount int32
	// Max number of units to scan concurrently per source.
	concurrentUnits int
	// Run the sources using source unit enumeration / chunking if available.
	useSourceUnits bool
	// Downstream chunks channel to be scanned.
	outputChunks chan *Chunk
	// Set when Wait() returns.
	done bool
}

// apiClient is an interface for optionally communicating with an external API.
type apiClient interface {
	// GetIDs informs the API of the source that's about to run and returns
	// two identifiers used during source initialization.
	GetIDs(ctx context.Context, name string, kind sourcespb.SourceType) (SourceID, JobID, error)
}

// WithAPI adds an API client to the manager for tracking jobs and progress. If
// the API is also a JobProgressHook, it will be added to the list of event hooks.
func WithAPI(api apiClient) func(*SourceManager) {
	return func(mgr *SourceManager) { mgr.api = api }
}

func WithReportHook(hook JobProgressHook) func(*SourceManager) {
	return func(mgr *SourceManager) {
		mgr.hooks = append(mgr.hooks, hook)
	}
}

// WithConcurrentSources limits the concurrent number of sources a manager can run.
func WithConcurrentSources(concurrency int) func(*SourceManager) {
	return func(mgr *SourceManager) {
		mgr.pool.SetLimit(concurrency)
		mgr.poolLimit = concurrency
	}
}

// WithBufferedOutput sets the size of the buffer used for the Chunks() channel.
func WithBufferedOutput(size int) func(*SourceManager) {
	return func(mgr *SourceManager) { mgr.outputChunks = make(chan *Chunk, size) }
}

// WithSourceUnits enables using source unit enumeration and chunking if the
// source supports it.
func WithSourceUnits() func(*SourceManager) {
	return func(mgr *SourceManager) { mgr.useSourceUnits = true }
}

// WithConcurrentUnits limits the number of units to be scanned concurrently.
// The default is unlimited.
func WithConcurrentUnits(n int) func(*SourceManager) {
	return func(mgr *SourceManager) { mgr.concurrentUnits = n }
}

// NewManager creates a new manager with the provided options.
func NewManager(opts ...func(*SourceManager)) *SourceManager {
	mgr := SourceManager{
		// Default to the headless API. Can be overwritten by the WithAPI option.
		api:          &headlessAPI{},
		outputChunks: make(chan *Chunk),
	}
	for _, opt := range opts {
		opt(&mgr)
	}
	return &mgr
}

func (s *SourceManager) GetIDs(ctx context.Context, sourceName string, kind sourcespb.SourceType) (SourceID, JobID, error) {
	return s.api.GetIDs(ctx, sourceName, kind)
}

// Run blocks until a resource is available to run the source, then
// asynchronously runs it. Error information is stored and accessible via the
// JobProgressRef as it becomes available.
func (s *SourceManager) Run(ctx context.Context, sourceName string, source Source) (JobProgressRef, error) {
	return s.asyncRun(ctx, sourceName, source)
}

// asyncRun is a helper method to asynchronously run the Source. It calls out
// to the API to get a job ID for this run, creates a JobProgress object, then
// waits for an available goroutine to asynchronously run it.
func (s *SourceManager) asyncRun(ctx context.Context, sourceName string, source Source) (JobProgressRef, error) {
	sourceID, jobID := source.SourceID(), source.JobID()
	// Do preflight checks before waiting on the pool.
	if err := s.preflightChecks(ctx); err != nil {
		return JobProgressRef{
			SourceName: sourceName,
			SourceID:   sourceID,
			JobID:      jobID,
		}, err
	}
	// Create a JobProgress object for tracking progress.
	ctx, cancel := context.WithCancelCause(ctx)
	progress := NewJobProgress(jobID, sourceID, sourceName, WithHooks(s.hooks...), WithCancel(cancel))
	s.pool.Go(func() error {
		atomic.AddInt32(&s.currentRunningCount, 1)
		defer atomic.AddInt32(&s.currentRunningCount, -1)
		ctx := context.WithValues(ctx,
			"job_id", jobID,
			"source_manager_worker_id", common.RandomID(5),
		)
		defer common.Recover(ctx)
		defer cancel(nil)
		return s.run(ctx, source, progress)
	})
	return progress.Ref(), nil
}

// Chunks returns the read only channel of all the chunks produced by all of
// the sources managed by this manager.
func (s *SourceManager) Chunks() <-chan *Chunk {
	return s.outputChunks
}

// Wait blocks until all running sources are completed and closes the channel
// returned by Chunks(). The manager should not be reused after calling this
// method. This current implementation is not thread safe and should only be
// called by one thread.
func (s *SourceManager) Wait() error {
	// Check if the manager has been Waited.
	if s.done {
		return s.pool.Wait()
	}
	defer close(s.outputChunks)
	defer func() { s.done = true }()

	// Return the first error returned by run.
	return s.pool.Wait()
}

// ScanChunk injects a chunk into the output stream of chunks to be scanned.
// This method should rarely be used. TODO: Remove when dependencies no longer
// rely on this functionality.
func (s *SourceManager) ScanChunk(chunk *Chunk) {
	s.outputChunks <- chunk
}

// AvailableCapacity returns the number of concurrent jobs the manager can
// accommodate at this time. If there is no limit, -1 is returned.
func (s *SourceManager) AvailableCapacity() int {
	if s.poolLimit == 0 {
		return -1
	}
	runCount := atomic.LoadInt32(&s.currentRunningCount)
	return s.poolLimit - int(runCount)
}

// preflightChecks is a helper method to check the Manager or the context isn't
// done.
func (s *SourceManager) preflightChecks(ctx context.Context) error {
	// Check if the manager has been Waited.
	if s.done {
		return fmt.Errorf("manager is done")
	}
	return ctx.Err()
}

// run is a helper method to sychronously run the source. It does not check for
// acquired resources. An error is returned if there was a fatal error during
// the run. This information is also recorded in the JobProgress.
func (s *SourceManager) run(ctx context.Context, source Source, report *JobProgress) error {
	defer report.Finish()
	report.Start(time.Now())
	defer func() { report.End(time.Now()) }()

	defer func() {
		if err := context.Cause(ctx); err != nil {
			report.ReportError(Fatal{err})
		}
	}()

	report.TrackProgress(source.GetProgress())
	ctx = context.WithValues(ctx,
		"source_type", source.Type().String(),
		"source_name", report.SourceName,
	)
	// Check for the preferred method of tracking source units.
	if enumChunker, ok := source.(SourceUnitEnumChunker); ok && s.useSourceUnits {
		return s.runWithUnits(ctx, enumChunker, report)
	}
	return s.runWithoutUnits(ctx, source, report)
}

// runWithoutUnits is a helper method to run a Source. It has coarse-grained
// job reporting.
func (s *SourceManager) runWithoutUnits(ctx context.Context, source Source, report *JobProgress) error {
	// Introspect on the chunks we get from the Chunks method.
	ch := make(chan *Chunk, 1)
	var wg sync.WaitGroup
	// Consume chunks and export chunks.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for chunk := range ch {
			chunk.JobID = source.JobID()
			report.ReportChunk(nil, chunk)
			s.outputChunks <- chunk
		}
	}()
	// Don't return from this function until the goroutine has finished
	// outputting chunks to the downstream channel. Closing the channel
	// will stop the goroutine, so that needs to happen first in the defer
	// stack.
	defer wg.Wait()
	defer close(ch)
	if err := source.Chunks(ctx, ch); err != nil {
		report.ReportError(Fatal{err})
		return Fatal{err}
	}
	return nil
}

// runWithUnits is a helper method to run a Source that is also a
// SourceUnitEnumChunker. This allows better introspection of what is getting
// scanned and any errors encountered.
func (s *SourceManager) runWithUnits(ctx context.Context, source SourceUnitEnumChunker, report *JobProgress) error {
	unitReporter := &mgrUnitReporter{
		unitCh: make(chan SourceUnit, 1),
		report: report,
	}
	// Create a function that will save the first error encountered (if
	// any) and discard the rest.
	fatalErr := make(chan error, 1)
	catchFirstFatal := func(err error) {
		select {
		case fatalErr <- err:
		default:
		}
	}
	// Produce units.
	go func() {
		// TODO: Catch panics and add to report.
		report.StartEnumerating(time.Now())
		defer func() { report.EndEnumerating(time.Now()) }()
		defer close(unitReporter.unitCh)
		ctx.Logger().V(2).Info("enumerating source")
		if err := source.Enumerate(ctx, unitReporter); err != nil {
			report.ReportError(Fatal{err})
			catchFirstFatal(Fatal{err})
		}
	}()
	var wg sync.WaitGroup
	// TODO: Maybe switch to using a semaphore.Weighted.
	var unitPool errgroup.Group
	if s.concurrentUnits != 0 {
		// Negative values indicated no limit.
		unitPool.SetLimit(s.concurrentUnits)
	}
	for unit := range unitReporter.unitCh {
		unit := unit
		chunkReporter := &mgrChunkReporter{
			unit:    unit,
			chunkCh: make(chan *Chunk, 1),
			report:  report,
		}
		// Consume units and produce chunks.
		unitPool.Go(func() error {
			report.StartUnitChunking(unit, time.Now())
			// TODO: Catch panics and add to report.
			defer close(chunkReporter.chunkCh)
			ctx := context.WithValue(ctx, "unit", unit.SourceUnitID())
			ctx.Logger().V(3).Info("chunking unit")
			if err := source.ChunkUnit(ctx, unit, chunkReporter); err != nil {
				report.ReportError(Fatal{err})
				catchFirstFatal(Fatal{err})
			}
			return nil
		})
		// Consume chunks and export chunks.
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { report.EndUnitChunking(unit, time.Now()) }()
			for chunk := range chunkReporter.chunkCh {
				if src, ok := source.(Source); ok {
					chunk.JobID = src.JobID()
				}
				s.outputChunks <- chunk
			}
		}()
	}
	wg.Wait()
	select {
	case err := <-fatalErr:
		return err
	default:
		return nil
	}
}

// headlessAPI implements the apiClient interface locally.
type headlessAPI struct {
	// Counters for assigning source and job IDs.
	sourceIDCounter int64
	jobIDCounter    int64
}

func (api *headlessAPI) GetIDs(context.Context, string, sourcespb.SourceType) (SourceID, JobID, error) {
	return SourceID(atomic.AddInt64(&api.sourceIDCounter, 1)), JobID(atomic.AddInt64(&api.jobIDCounter, 1)), nil
}

// mgrUnitReporter implements the UnitReporter interface.
type mgrUnitReporter struct {
	unitCh chan SourceUnit
	report *JobProgress
}

func (s *mgrUnitReporter) UnitOk(ctx context.Context, unit SourceUnit) error {
	s.report.ReportUnit(unit)
	return common.CancellableWrite(ctx, s.unitCh, unit)
}

func (s *mgrUnitReporter) UnitErr(ctx context.Context, err error) error {
	s.report.ReportError(err)
	return nil
}

// mgrChunkReporter implements the ChunkReporter interface.
type mgrChunkReporter struct {
	unit    SourceUnit
	chunkCh chan *Chunk
	report  *JobProgress
}

func (s *mgrChunkReporter) ChunkOk(ctx context.Context, chunk Chunk) error {
	s.report.ReportChunk(s.unit, &chunk)
	return common.CancellableWrite(ctx, s.chunkCh, &chunk)
}

func (s *mgrChunkReporter) ChunkErr(ctx context.Context, err error) error {
	s.report.ReportError(ChunkError{s.unit, err})
	return nil
}
