package sources

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"golang.org/x/sync/errgroup"
)

// handle uniquely identifies a Source given to the manager to manage. If the
// SourceManager is connected to the API, it will be equivalent to the unique
// source ID, otherwise it behaves as a counter.
type handle int64

// SourceInitFunc is a function that takes a source and job ID and returns an
// initialized Source.
type SourceInitFunc func(ctx context.Context, sourceID int64, jobID int64) (Source, error)

type SourceManager struct {
	api apiClient
	// Map of handle to source initializer.
	handles     map[handle]SourceInitFunc
	handlesLock sync.Mutex
	// Map of handle to job reports.
	// TODO: Manage culling and flushing to the API.
	report     map[handle]*JobReport
	reportLock sync.Mutex
	// Pool limiting the amount of concurrent sources running.
	pool            errgroup.Group
	concurrentUnits int
	// Run the sources using source unit enumeration / chunking if available.
	useSourceUnits bool
	// Downstream chunks channel to be scanned.
	outputChunks chan *Chunk
	// Set when Wait() returns.
	done    bool
	doneErr error
}

// apiClient is an interface for optionally communicating with an external API.
type apiClient interface {
	// RegisterSource lets the API know we have a source and it returns a unique source ID for it.
	RegisterSource(ctx context.Context, name string, kind sourcespb.SourceType) (int64, error)
	// GetJobID queries the API for an existing job or new job ID.
	GetJobID(ctx context.Context, id int64) (int64, error)
}

// WithAPI adds an API client to the manager for tracking jobs and progress.
func WithAPI(api apiClient) func(*SourceManager) {
	return func(mgr *SourceManager) { mgr.api = api }
}

// WithConcurrency limits the concurrent number of sources a manager can run.
func WithConcurrency(concurrency int) func(*SourceManager) {
	return func(mgr *SourceManager) { mgr.pool.SetLimit(concurrency) }
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
		handles:      make(map[handle]SourceInitFunc),
		report:       make(map[handle]*JobReport),
		outputChunks: make(chan *Chunk),
	}
	for _, opt := range opts {
		opt(&mgr)
	}
	return &mgr
}

// Enroll informs the SourceManager to track and manage a Source.
func (s *SourceManager) Enroll(ctx context.Context, name string, kind sourcespb.SourceType, f SourceInitFunc) (handle, error) {
	if s.done {
		return 0, fmt.Errorf("manager is done")
	}
	id, err := s.api.RegisterSource(ctx, name, kind)
	if err != nil {
		return 0, err
	}
	handleID := handle(id)
	s.handlesLock.Lock()
	defer s.handlesLock.Unlock()
	if _, ok := s.handles[handleID]; ok {
		// TODO: smartly handle this?
		return 0, fmt.Errorf("handle ID '%d' already in use", handleID)
	}
	s.handles[handleID] = f
	return handleID, nil
}

// Run blocks until a resource is available to run the source, then
// synchronously runs it.
func (s *SourceManager) Run(ctx context.Context, handle handle) error {
	// Do preflight checks before waiting on the pool.
	if err := s.preflightChecks(ctx, handle); err != nil {
		return err
	}
	ch := make(chan error)
	s.pool.Go(func() error {
		defer common.Recover(ctx)
		report, err := s.run(ctx, handle)
		if report != nil {
			s.reportLock.Lock()
			s.report[handle] = report
			s.reportLock.Unlock()
		}
		if err != nil {
			ch <- err
			return nil
		}
		ch <- report.Errors()
		return nil
	})
	return <-ch
}

// ScheduleRun blocks until a resource is available to run the source, then
// asynchronously runs it. Error information is stored and returned by Wait().
func (s *SourceManager) ScheduleRun(ctx context.Context, handle handle) error {
	// Do preflight checks before waiting on the pool.
	if err := s.preflightChecks(ctx, handle); err != nil {
		return err
	}
	s.pool.Go(func() error {
		defer common.Recover(ctx)
		// The error is already saved in the report, so we can ignore
		// it here.
		report, _ := s.run(ctx, handle)
		if report != nil {
			s.reportLock.Lock()
			s.report[handle] = report
			s.reportLock.Unlock()
		}
		return nil
	})
	// TODO: Maybe wait for a signal here that initialization was successful?
	return nil
}

// Chunks returns the read only channel of all the chunks produced by all of
// the sources managed by this manager.
func (s *SourceManager) Chunks() <-chan *Chunk {
	return s.outputChunks
}

// Wait blocks until all running sources are completed and returns an error if
// any of the sources had fatal errors. It also closes the channel returned by
// Chunks(). The manager should not be reused after calling this method.
func (s *SourceManager) Wait() error {
	// Check if the manager has been Waited.
	if s.done {
		return s.doneErr
	}
	defer close(s.outputChunks)
	defer func() { s.done = true }()

	// We are only using the errgroup for limiting concurrency.
	// TODO: Maybe switch to using a semaphore.Weighted.
	_ = s.pool.Wait()

	// Aggregate the first fatal errors from all job reports.
	s.reportLock.Lock()
	defer s.reportLock.Unlock()
	errs := make([]error, 0, len(s.report))
	for _, report := range s.report {
		errs = append(errs, report.FatalError())
	}
	s.doneErr = errors.Join(errs...)
	return s.doneErr
}

// Report retrieves a scan report for a given handle. If no report exists or
// the Source has not finished, nil will be returned.
func (s *SourceManager) Report(handle handle) *JobReport {
	s.reportLock.Lock()
	defer s.reportLock.Unlock()
	return s.report[handle]
}

// preflightChecks is a helper method to check the Manager or the context isn't
// done and that the handle is valid.
func (s *SourceManager) preflightChecks(ctx context.Context, handle handle) error {
	// Check if the manager has been Waited.
	if s.done {
		return fmt.Errorf("manager is done")
	}
	// Check the handle is valid.
	if _, ok := s.getInitFunc(handle); !ok {
		return fmt.Errorf("unrecognized handle")
	}
	return ctx.Err()
}

// run is a helper method to sychronously run the source. It does not check for
// acquired resources. Possible return values are:
//
//   - *JobReport, nil
//     Successfully ran the source, but the report could have errors.
//
//   - *JobReport, error
//     There was an error calling Init or Chunks. This sort of error indicates
//     a fatal error and is also recorded in the report.
//
//   - nil, error:
//     There was an error from the API or the handle is invalid. The latter of
//     which should never happen due to the preflightChecks.
func (s *SourceManager) run(ctx context.Context, handle handle) (*JobReport, error) {
	jobID, err := s.api.GetJobID(ctx, int64(handle))
	if err != nil {
		return nil, err
	}
	initFunc, ok := s.getInitFunc(handle)
	if !ok {
		return nil, fmt.Errorf("unrecognized handle")
	}
	// Create a report for this run.
	report := &JobReport{
		SourceID:  int64(handle),
		JobID:     jobID,
		StartTime: time.Now(),
	}
	defer func() { report.EndTime = time.Now() }()

	// Initialize the source.
	source, err := initFunc(ctx, jobID, int64(handle))
	if err != nil {
		report.AddError(Fatal{err})
		return report, Fatal{err}
	}
	// Check for the preferred method of tracking source units.
	if enumChunker, ok := source.(SourceUnitEnumChunker); ok && s.useSourceUnits {
		return s.runWithUnits(ctx, handle, enumChunker, report)
	}
	return s.runWithoutUnits(ctx, handle, source, report)
}

// runWithoutUnits is a helper method to run a Source. It has coarse-grained
// job reporting.
func (s *SourceManager) runWithoutUnits(ctx context.Context, handle handle, source Source, report *JobReport) (*JobReport, error) {
	// Introspect on the chunks we get from the Chunks method.
	ch := make(chan *Chunk)
	var wg sync.WaitGroup
	// Consume chunks and export chunks.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for chunk := range ch {
			atomic.AddUint64(&report.TotalChunks, 1)
			_ = common.CancellableWrite(ctx, s.outputChunks, chunk)
		}
	}()
	// Don't return from this function until the goroutine has finished
	// outputting chunks to the downstream channel. Closing the channel
	// will stop the goroutine, so that needs to happen first in the defer
	// stack.
	defer wg.Wait()
	defer close(ch)
	if err := source.Chunks(ctx, ch); err != nil {
		report.AddChunkError(nil, Fatal{err})
		return report, Fatal{err}
	}
	return report, nil
}

// runWithUnits is a helper method to run a Source that is also a
// SourceUnitEnumChunker. This allows better introspection of what is getting
// scanned and any errors encountered.
func (s *SourceManager) runWithUnits(ctx context.Context, handle handle, source SourceUnitEnumChunker, report *JobReport) (*JobReport, error) {
	reporter := &mgrUnitReporter{
		unitCh: make(chan SourceUnit),
		report: report,
	}
	// Produce units.
	go func() {
		// TODO: Catch panics and add to report.
		defer close(reporter.unitCh)
		if err := source.Enumerate(ctx, reporter); err != nil {
			report.AddError(Fatal{err})
		}
	}()
	var wg sync.WaitGroup
	// TODO: Maybe switch to using a semaphore.Weighted.
	var unitPool errgroup.Group
	if s.concurrentUnits != 0 {
		// Negative values indicated no limit.
		unitPool.SetLimit(s.concurrentUnits)
	}
	for unit := range reporter.unitCh {
		unit := unit
		reporter := &mgrChunkReporter{
			unit:    unit,
			chunkCh: make(chan *Chunk),
			report:  report,
		}
		// Consume units and produce chunks.
		unitPool.Go(func() error {
			// TODO: Catch panics and add to report.
			defer close(reporter.chunkCh)
			if err := source.ChunkUnit(ctx, unit, reporter); err != nil {
				report.AddError(Fatal{err})
			}
			return nil
		})
		// Consume chunks and export chunks.
		wg.Add(1)
		go func() {
			defer wg.Done()
			for chunk := range reporter.chunkCh {
				// TODO: Introspect on the chunks we got from this unit.
				atomic.AddUint64(&report.TotalChunks, 1)
				_ = common.CancellableWrite(ctx, s.outputChunks, chunk)
			}
		}()
	}
	wg.Wait()
	return report, report.FatalError()
}

// getInitFunc is a helper method for safe concurrent access to the
// map[handle]SourceInitFunc map.
func (s *SourceManager) getInitFunc(handle handle) (SourceInitFunc, bool) {
	s.handlesLock.Lock()
	defer s.handlesLock.Unlock()
	f, ok := s.handles[handle]
	return f, ok
}

// headlessAPI implements the apiClient interface locally.
type headlessAPI struct {
	// Counters for assigning handle and job IDs.
	sourceIDCounter int64
	jobIDCounter    int64
}

func (api *headlessAPI) RegisterSource(ctx context.Context, name string, kind sourcespb.SourceType) (int64, error) {
	return atomic.AddInt64(&api.sourceIDCounter, 1), nil
}

func (api *headlessAPI) GetJobID(ctx context.Context, id int64) (int64, error) {
	return atomic.AddInt64(&api.jobIDCounter, 1), nil
}

// mgrUnitReporter implements the UnitReporter interface.
type mgrUnitReporter struct {
	unitCh chan SourceUnit
	report *JobReport
}

func (s *mgrUnitReporter) UnitOk(ctx context.Context, unit SourceUnit) error {
	return common.CancellableWrite(ctx, s.unitCh, unit)
}

func (s *mgrUnitReporter) UnitErr(ctx context.Context, err error) error {
	s.report.AddError(err)
	return nil
}

// mgrChunkReporter implements the ChunkReporter interface.
type mgrChunkReporter struct {
	unit    SourceUnit
	chunkCh chan *Chunk
	report  *JobReport
}

func (s *mgrChunkReporter) ChunkOk(ctx context.Context, chunk Chunk) error {
	return common.CancellableWrite(ctx, s.chunkCh, &chunk)
}

func (s *mgrChunkReporter) ChunkErr(ctx context.Context, err error) error {
	s.report.AddChunkError(s.unit, err)
	return nil
}
