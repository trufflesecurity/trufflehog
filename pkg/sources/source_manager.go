package sources

import (
	"fmt"
	"sync"
	"sync/atomic"

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
type SourceInitFunc func(sourceID int64, jobID int64) (Source, error)

type SourceManager struct {
	api apiClient
	// Map of handle to source initializer.
	handles     map[handle]SourceInitFunc
	handlesLock sync.Mutex
	// Pool limiting the amount of concurrent sources running.
	pool errgroup.Group
	// Downstream chunks channel to be scanned.
	outputChunks chan *Chunk
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
	return func(man *SourceManager) { man.api = api }
}

// WithConcurrency limits the concurrent number of sources a manager can run.
func WithConcurrency(concurrency int) func(*SourceManager) {
	return func(man *SourceManager) { man.pool.SetLimit(concurrency) }
}

// NewManager creates a new manager with the provided options.
func NewManager(outputChunks chan *Chunk, opts ...func(*SourceManager)) *SourceManager {
	man := SourceManager{
		// Default to the headless API. Can be overwritten by the WithAPI option.
		api:          &headlessAPI{},
		handles:      make(map[handle]SourceInitFunc),
		outputChunks: outputChunks,
	}
	for _, opt := range opts {
		opt(&man)
	}
	return &man
}

// Enroll informs the SourceManager to track and manage a Source.
func (s *SourceManager) Enroll(ctx context.Context, name string, kind sourcespb.SourceType, f SourceInitFunc) (handle, error) {
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
	return 0, nil
}

// Run blocks until a resource is available to run the source, then synchronously runs it.
func (s *SourceManager) Run(ctx context.Context, handle handle) error {
	// Check the handle is valid before waiting on the pool.
	if _, ok := s.getInitFunc(handle); !ok {
		return fmt.Errorf("unrecognized handle")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	ch := make(chan error)
	s.pool.Go(func() error {
		defer common.Recover(ctx)
		// TODO: The manager should record these errors.
		ch <- s.run(ctx, handle)
		return nil
	})
	return <-ch
}

// ScheduleRun blocks until a resource is available to run the source, then
// asynchronously runs it. Error information is lost in this case.
func (s *SourceManager) ScheduleRun(ctx context.Context, handle handle) error {
	// Check the handle is valid before waiting on the pool.
	if _, ok := s.getInitFunc(handle); !ok {
		return fmt.Errorf("unrecognized handle")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.pool.Go(func() error {
		defer common.Recover(ctx)
		// TODO: The manager should record these errors.
		_ = s.run(ctx, handle)
		return nil
	})
	// TODO: Maybe wait for a signal here that initialization was successful?
	return nil
}

// run is a helper method to sychronously run the source. It does not check for
// acquired resources.
func (s *SourceManager) run(ctx context.Context, handle handle) error {
	jobID, err := s.api.GetJobID(ctx, int64(handle))
	if err != nil {
		return err
	}
	initFunc, ok := s.getInitFunc(handle)
	if !ok {
		return fmt.Errorf("unrecognized handle")
	}
	source, err := initFunc(jobID, int64(handle))
	if err != nil {
		return err
	}
	// TODO: Support UnitChunker and SourceUnitEnumerator.
	// TODO: This is where we can introspect on the chunks collected.
	return source.Chunks(ctx, s.outputChunks)
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
