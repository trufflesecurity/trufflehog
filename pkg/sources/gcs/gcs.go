package gcs

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"sync"

	diskbufferreader "github.com/bill-rich/disk-buffer-reader"
	"github.com/go-errors/errors"
	"github.com/go-logr/logr"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/handlers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

// Source represents a GCS source.
type Source struct {
	name        string
	jobId       int64
	sourceId    int64
	concurrency int
	verify      bool

	gcsManager objectManager
	log        logr.Logger
	chunksCh   chan *sources.Chunk
	sources.Progress
}

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

	var gcsManagerAuthOption gcsManagerOption

	switch conn.Credential.(type) {
	case *sourcespb.GCS_ApiKey:
		gcsManagerAuthOption = withAPIKey(aCtx, conn.GetApiKey())
	case *sourcespb.GCS_JsonSa:
		b, err := os.ReadFile(conn.GetJsonSa())
		if err != nil {
			return fmt.Errorf("error reading GCS JSON Service Account file: %w", err)
		}
		gcsManagerAuthOption = withJSONServiceAccount(aCtx, b)
	case *sourcespb.GCS_Adc:
		gcsManagerAuthOption = withDefaultADC(aCtx)
	case *sourcespb.GCS_Unauthenticated:
		gcsManagerAuthOption = withoutAuthentication()
	default:
		return fmt.Errorf("unknown GCS authentication type: %T", conn.Credential)

	}

	resume, err := setResumeBucketOffset(s.Progress.EncodedResumeInfo)
	if err != nil {
		return fmt.Errorf("error setting resume info: %w", err)
	}

	gcsManagerOpts := []gcsManagerOption{
		withConcurrency(concurrency),
		withBucketOffsets(resume),
		withMaxObjectSize(conn.MaxObjectSize),
		gcsManagerAuthOption,
	}
	if setGCSManagerBucketOptions(&conn) != nil {
		gcsManagerOpts = append(gcsManagerOpts, setGCSManagerBucketOptions(&conn))
	}
	if setGCSManagerObjectOptions(&conn) != nil {
		gcsManagerOpts = append(gcsManagerOpts, setGCSManagerObjectOptions(&conn))
	}

	if s.gcsManager, err = newGCSManager(conn.ProjectId, gcsManagerOpts...); err != nil {
		return fmt.Errorf("error creating GCS manager: %w", err)
	}

	return nil
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

type resumeInfo struct {
	mu sync.RWMutex
	// bucketObjects tracks processing and processed objects for each bucket.
	bucketObjects map[string]*objectsProgress
}

func newResumeInfo() *resumeInfo {
	return &resumeInfo{bucketObjects: make(map[string]*objectsProgress)}
}

type progressStateFn func(string, string, *resumeInfo)

func (r *resumeInfo) setProcessStatus(obj object, fn progressStateFn) map[string]*objectsProgress {
	r.createBucketObject(obj.bucket)
	fn(obj.bucket, obj.name, r)

	return r.bucketObjects
}

func (r *resumeInfo) createBucketObject(bucket string) {
	if !r.doesBucketExist(bucket) {
		r.newBucketObjects(bucket)
	}
}

func (r *resumeInfo) doesBucketExist(bucket string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	_, ok := r.bucketObjects[bucket]
	return ok
}

func (r *resumeInfo) newBucketObjects(bucket string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.bucketObjects[bucket] = newObjectsProgress()
}

func setProcessingBucketObject(bucket, obj string, r *resumeInfo) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.bucketObjects[bucket].Processing[obj] = struct{}{}
}

func setProcessedBucketObject(bucket, obj string, r *resumeInfo) {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.bucketObjects[bucket].Processing, obj)

	// If the object is not greater (lexicographically) than the last processed object, we can skip it.
	// This ensures we keep the greatest object name as the last processed object.
	if obj < r.bucketObjects[bucket].Processed {
		return
	}
	r.bucketObjects[bucket].Processed = obj
}

type objectsProgress struct {
	// Processing are the objects that were not fully processed.
	Processing map[string]struct{}
	// Processed is the last object that was fully processed.
	Processed string
}

func newObjectsProgress() *objectsProgress {
	return &objectsProgress{Processing: map[string]struct{}{}}
}

func setResumeBucketOffset(s string) (map[string]string, error) {
	resumeInfo := resumeInfo{}
	if s != "" {
		if err := json.Unmarshal([]byte(s), &resumeInfo.bucketObjects); err != nil {
			return nil, fmt.Errorf("error unmarshalling resume info: %w", err)
		}
	}

	return calcBktOffset(resumeInfo.bucketObjects)
}

// In order to calculate the bucket offset, we need to know the last object
// that was processed for each bucket, as well as any objects that were processing.
// If there were no objects processing, we can just use the last object that was processed.
// If there were objects processing, we need to find the first object (lexicographically)
// that was processing, as that is the next object that needs to be processed.
func calcBktOffset(resumeInfo map[string]*objectsProgress) (map[string]string, error) {
	bucketOffset := make(map[string]string, len(resumeInfo))
	for k, v := range resumeInfo {
		if len(v.Processing) == 0 {
			bucketOffset[k] = v.Processed
			continue
		}

		processing := make([]string, 0, len(v.Processing))
		for k := range v.Processing {
			processing = append(processing, k)
		}
		sort.Strings(processing)
		bucketOffset[k] = processing[0]
	}

	return bucketOffset, nil
}

// Chunks emits chunks of bytes over a channel.
func (s *Source) Chunks(ctx context.Context, chunksChan chan *sources.Chunk) error {
	objectCh, err := s.gcsManager.listObjects(ctx)
	if err != nil {
		return fmt.Errorf("error listing objects: %w", err)
	}
	s.chunksCh = chunksChan

	resume := newResumeInfo()

	var wg sync.WaitGroup
	for obj := range objectCh {
		obj := obj
		o, ok := obj.(object)
		if !ok {
			ctx.Logger().Error(fmt.Errorf("unexpected object type: %T", obj), "GCS source unexpected object type", "name", s.name)
			continue
		}

		if err := s.startProcessing(ctx, resume, o); err != nil {
			ctx.Logger().V(1).Info("GCS source error starting to process objects", "error", err)
			continue
		}
		wg.Add(1)
		go func(obj object, resume *resumeInfo) {
			defer wg.Done()

			if err := s.processObject(ctx, o); err != nil {
				ctx.Logger().V(1).Info("error setting start resume progress", "name", o.name, "error", err)
				return
			}
			if err := s.endProcessing(ctx, resume, o); err != nil {
				ctx.Logger().V(1).Info("error setting end resume progress", "name", o.name, "error", err)
			}
		}(o, resume)
	}
	wg.Wait()

	ctx.Logger().Info("GCS source finished processing", "name", s.name)
	return nil
}

func (s *Source) startProcessing(ctx context.Context, resume *resumeInfo, o object) error {
	p := resume.setProcessStatus(o, setProcessingBucketObject)
	msg := fmt.Sprintf("GCS source beginning to process object %s in bucket %s", o.name, o.bucket)
	ctx.Logger().V(5).Info(msg)

	b, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("error marshalling resume info for object %s in bucket %s: %w", o.name, o.bucket, err)
	}
	s.SetProgressComplete(0, 0, msg, string(b))

	return nil
}

func (s *Source) endProcessing(ctx context.Context, resume *resumeInfo, o object) error {
	p := resume.setProcessStatus(o, setProcessedBucketObject)
	msg := fmt.Sprintf("GCS source finished processing object %s in bucket %s", o.name, o.bucket)
	ctx.Logger().V(5).Info(msg)

	b, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("error marshalling resume info for object %s in bucket %s: %w", o.name, o.bucket, err)
	}
	s.SetProgressComplete(0, 0, msg, string(b))

	return nil
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
