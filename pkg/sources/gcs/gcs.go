package gcs

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	diskbufferreader "github.com/bill-rich/disk-buffer-reader"
	"github.com/go-errors/errors"
	"github.com/go-logr/logr"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/cache"
	"github.com/trufflesecurity/trufflehog/v3/pkg/cache/memory"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/handlers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

const defaultCacheThreshold = 0.01

// Ensure the Source satisfies the interface at compile time.
var _ sources.Source = (*Source)(nil)

// Type returns the type of source.
// It is used for matching source types in configuration and job input.
func (s *Source) Type() sourcespb.SourceType {
	return sourcespb.SourceType_SOURCE_TYPE_GCS
}

// SourceID number for GCS Source.
func (s *Source) SourceID() int64 {
	return s.sourceId
}

// JobID number for GCS Source.
func (s *Source) JobID() int64 {
	return s.jobId
}

// Source represents a GCS source.
type Source struct {
	name        string
	jobId       int64
	sourceId    int64
	concurrency int
	verify      bool

	gcsManager objectManager
	stats      *attributes
	log        logr.Logger
	chunksCh   chan *sources.Chunk

	processedObjects int32
	cacheMgr         *cacheManager

	sources.Progress
}

// cacheManager handles all cache operations with some additional bookkeeping.
// The threshold value is the percentage of objects that must be processed
// before the cache is persisted.
type cacheManager struct {
	shouldCache bool
	threshold   int
	cache       cache.Cache
	progress    *sources.Progress
}

// newCacheManager creates the cache manager with the given threshold.
func newCacheManager(threshold int, cache cache.Cache, p *sources.Progress) *cacheManager {
	// If the threshold is <= 1, there is not benefit to caching.
	shouldCache := threshold > 1
	return &cacheManager{
		shouldCache: shouldCache,
		threshold:   threshold,
		cache:       cache,
		progress:    p,
	}
}

func (c *cacheManager) exists(key string) bool {
	return c.cache.Exists(key)
}

func (c *cacheManager) set(key string) {
	c.cache.Set(key, key)
}

func (c *cacheManager) shouldPersist() (bool, string) {
	if !c.shouldCache {
		return false, ""
	}

	if c.cache.Count()%c.threshold != 0 {
		return false, ""
	}
	return true, c.cache.Contents()
}

func (c *cacheManager) flush() {
	c.cache.Clear()
}

// Init returns an initialized GCS source.
func (s *Source) Init(aCtx context.Context, name string, id int64, sourceID int64, verify bool, connection *anypb.Any, concurrency int) error {
	s.log = aCtx.Logger()

	s.name = name
	s.verify = verify
	s.sourceId = sourceID
	s.jobId = id
	s.concurrency = concurrency

	var conn sourcespb.GCS
	err := anypb.UnmarshalTo(connection, &conn, proto.UnmarshalOptions{})
	if err != nil {
		return errors.WrapPrefix(err, "error unmarshalling connection", 0)
	}

	gcsManager, err := configureGCSManager(aCtx, &conn, concurrency)
	if err != nil {
		return err
	}
	s.gcsManager = gcsManager

	s.log.V(2).Info("enumerating buckets and objects")
	if err := s.enumerate(aCtx); err != nil {
		return fmt.Errorf("error enumerating buckets and objects: %w", err)
	}

	var c cache.Cache
	if s.Progress.EncodedResumeInfo != "" {
		c = memory.NewWithData(aCtx, strings.Split(s.Progress.EncodedResumeInfo, ","))
	} else {
		c = memory.New()
	}

	// Set the threshold to 1% of the total number of objects.
	thresh := int(float64(s.stats.numObjects) * defaultCacheThreshold)
	s.cacheMgr = newCacheManager(thresh, c, &s.Progress)

	return nil
}

func configureGCSManager(aCtx context.Context, conn *sourcespb.GCS, concurrency int) (*gcsManager, error) {
	if conn == nil {
		return nil, fmt.Errorf("GCS connection is nil, cannot configure GCS manager")
	}

	var gcsManagerAuthOption gcsManagerOption

	switch conn.Credential.(type) {
	case *sourcespb.GCS_ApiKey:
		gcsManagerAuthOption = withAPIKey(aCtx, conn.GetApiKey())
	case *sourcespb.GCS_ServiceAccountFile:
		b, err := os.ReadFile(conn.GetServiceAccountFile())
		if err != nil {
			return nil, fmt.Errorf("error reading GCS JSON Service Account file: %w", err)
		}
		gcsManagerAuthOption = withJSONServiceAccount(aCtx, b)
	case *sourcespb.GCS_JsonServiceAccount:
		gcsManagerAuthOption = withJSONServiceAccount(aCtx, []byte(conn.GetJsonServiceAccount()))
	case *sourcespb.GCS_Adc:
		gcsManagerAuthOption = withDefaultADC(aCtx)
	case *sourcespb.GCS_Unauthenticated:
		gcsManagerAuthOption = withoutAuthentication()
	default:
		return nil, fmt.Errorf("unknown GCS authentication type: %T", conn.Credential)

	}

	gcsManagerOpts := []gcsManagerOption{
		withConcurrency(concurrency),
		withMaxObjectSize(conn.MaxObjectSize),
		gcsManagerAuthOption,
	}
	if setGCSManagerBucketOptions(conn) != nil {
		gcsManagerOpts = append(gcsManagerOpts, setGCSManagerBucketOptions(conn))
	}
	if setGCSManagerObjectOptions(conn) != nil {
		gcsManagerOpts = append(gcsManagerOpts, setGCSManagerObjectOptions(conn))
	}

	gcsManager, err := newGCSManager(conn.ProjectId, gcsManagerOpts...)
	if err != nil {
		return nil, fmt.Errorf("error creating GCS manager: %w", err)
	}

	return gcsManager, nil
}

func setGCSManagerBucketOptions(conn *sourcespb.GCS) gcsManagerOption {
	return setGCSManagerOptions(conn.GetIncludeBuckets(), conn.GetExcludeBuckets(), withIncludeBuckets, withExcludeBuckets)
}

func setGCSManagerObjectOptions(conn *sourcespb.GCS) gcsManagerOption {
	return setGCSManagerOptions(conn.GetIncludeObjects(), conn.GetExcludeObjects(), withIncludeObjects, withExcludeObjects)
}

func setGCSManagerOptions(include, exclude []string, includeFn, excludeFn func([]string) gcsManagerOption) gcsManagerOption {
	// Only allow one of include/exclude to be set.
	// If both are set, include takes precedence.
	if len(include) > 0 {
		return includeFn(include)
	}
	if len(exclude) > 0 {
		return excludeFn(exclude)
	}

	return nil
}

// enumerate all the objects and buckets in the source and use the results to
// set the progress information. This will be used track progression of the scan,
// and to resume the scan if it is interrupted.
func (s *Source) enumerate(ctx context.Context) error {
	stats, err := s.gcsManager.attributes(ctx)
	if err != nil {
		return fmt.Errorf("error getting attributes during enumeration: %w", err)
	}
	s.stats = stats

	return nil
}

// Chunks emits chunks of bytes over a channel.
func (s *Source) Chunks(ctx context.Context, chunksChan chan *sources.Chunk) error {
	objectCh, err := s.gcsManager.listObjects(ctx)
	if err != nil {
		return fmt.Errorf("error listing objects: %w", err)
	}
	s.chunksCh = chunksChan
	s.Progress.Message = "starting to process objects..."

	var wg sync.WaitGroup
	for obj := range objectCh {
		obj := obj
		o, ok := obj.(object)
		if !ok {
			ctx.Logger().Error(fmt.Errorf("unexpected object type: %T", obj), "GCS source unexpected object type", "name", s.name)
			continue
		}

		if s.cacheMgr.exists(o.name) {
			ctx.Logger().V(5).Info("skipping object, object already processed", "name", o.name)
			continue
		}

		wg.Add(1)
		go func(obj object) {
			defer wg.Done()

			if err := s.processObject(ctx, o); err != nil {
				ctx.Logger().V(1).Info("error setting start progress progress", "name", o.name, "error", err)
				return
			}
			s.setProgress(ctx, o.name)
		}(o)
	}
	wg.Wait()

	s.completeProgress(ctx)
	return nil
}

func (s *Source) setProgress(ctx context.Context, objName string) {
	atomic.AddInt32(&s.processedObjects, 1)
	ctx.Logger().V(5).Info("setting progress for object", "object-name", objName)

	s.cacheMgr.set(objName)
	if ok, val := s.cacheMgr.shouldPersist(); ok {
		s.SetProgressComplete(int(s.processedObjects), int(s.stats.numObjects), fmt.Sprintf("object %s processed", objName), val)
		return
	}
	processed := atomic.LoadInt32(&s.processedObjects)
	s.Progress.SectionsCompleted = processed
	s.Progress.SectionsRemaining = int32(s.stats.numObjects)
	s.Progress.PercentComplete = int64(float64(processed) / float64(s.stats.numObjects) * 100)

	return
}

func (s *Source) completeProgress(ctx context.Context) {
	msg := fmt.Sprintf("GCS source finished processing %d objects", s.stats.numObjects)
	ctx.Logger().Info(msg)
	s.Progress.Message = msg
	s.cacheMgr.flush()
}

func (s *Source) processObject(ctx context.Context, o object) error {
	chunkSkel := &sources.Chunk{
		SourceName: s.name,
		SourceType: s.Type(),
		SourceID:   s.sourceId,
		Verify:     s.verify,
		SourceMetadata: &source_metadatapb.MetaData{
			Data: &source_metadatapb.MetaData_Gcs{
				Gcs: &source_metadatapb.GCS{
					Bucket:      o.bucket,
					Filename:    o.name,
					Link:        o.link,
					Email:       o.owner,
					ContentType: o.contentType,
					Acls:        o.acl,
					CreatedAt:   o.createdAt.String(),
					UpdatedAt:   o.updatedAt.String(),
				},
			},
		},
	}

	data, err := s.readObjectData(ctx, o, chunkSkel)
	if err != nil {
		return fmt.Errorf("error reading object data: %w", err)
	}

	// If data is nil, it means that the file was handled by a handler.
	if data == nil {
		return nil
	}

	chunkSkel.Data = data

	select {
	case <-ctx.Done():
		return ctx.Err()
	case s.chunksCh <- chunkSkel:
	}

	return nil
}

func (s *Source) readObjectData(ctx context.Context, o object, chunk *sources.Chunk) ([]byte, error) {
	reader, err := diskbufferreader.New(o)
	if err != nil {
		return nil, fmt.Errorf("error creating disk buffer reader: %w", err)
	}
	defer reader.Close()

	if handlers.HandleFile(ctx, reader, chunk, s.chunksCh) {
		ctx.Logger().V(3).Info("File was handled", "name", s.name, "bucket", o.bucket, "object", o.name)
		return nil, nil
	}

	if err := reader.Reset(); err != nil {
		return nil, fmt.Errorf("error resetting reader: %w", err)
	}

	reader.Stop()
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("error reading object: %w", err)
	}

	return data, nil
}
