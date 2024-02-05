package gcs

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"

	"cloud.google.com/go/storage"
	"github.com/go-errors/errors"
	"github.com/go-logr/logr"
	diskbufferreader "github.com/trufflesecurity/disk-buffer-reader"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/endpoints"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/cache"
	"github.com/trufflesecurity/trufflehog/v3/pkg/cache/memory"
	"github.com/trufflesecurity/trufflehog/v3/pkg/cleantemp"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/handlers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/credentialspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

const (
	SourceType = sourcespb.SourceType_SOURCE_TYPE_GCS

	defaultCachePersistIncrement = 2500
)

// Ensure the Source satisfies the interfaces at compile time.
var _ sources.Source = (*Source)(nil)
var _ sources.SourceUnitUnmarshaller = (*Source)(nil)

// Type returns the type of source.
// It is used for matching source types in configuration and job input.
func (s *Source) Type() sourcespb.SourceType {
	return SourceType
}

// SourceID number for GCS Source.
func (s *Source) SourceID() sources.SourceID {
	return s.sourceId
}

// JobID number for GCS Source.
func (s *Source) JobID() sources.JobID {
	return s.jobId
}

type objectManager interface {
	ListObjects(context.Context) (chan io.Reader, error)
	Attributes(ctx context.Context) (*attributes, error)
}

// Source represents a GCS source.
type Source struct {
	name        string
	jobId       sources.JobID
	sourceId    sources.SourceID
	concurrency int
	verify      bool

	gcsManager objectManager
	stats      *attributes
	log        logr.Logger
	chunksCh   chan *sources.Chunk

	mu               sync.Mutex
	sources.Progress // progress is not thread safe
	sources.CommonSourceUnitUnmarshaller
}

// persistableCache is a wrapper around cache.Cache that allows
// for the persistence of the cache contents in the Progress of the source
// at given increments.
type persistableCache struct {
	persistIncrement int
	cache.Cache
	*sources.Progress
}

func newPersistableCache(increment int, cache cache.Cache, p *sources.Progress) *persistableCache {
	return &persistableCache{
		persistIncrement: increment,
		Cache:            cache,
		Progress:         p,
	}
}

// Set overrides the cache Set method of the cache to enable the persistence
// of the cache contents the Progress of the source at given increments.
func (c *persistableCache) Set(key string, val any) {
	c.Cache.Set(key, val)
	if ok, contents := c.shouldPersist(); ok {
		c.Progress.EncodedResumeInfo = contents
	}
}

func (c *persistableCache) shouldPersist() (bool, string) {
	if c.Count()%c.persistIncrement != 0 {
		return false, ""
	}
	return true, c.Contents()
}

// Init returns an initialized GCS source.
func (s *Source) Init(aCtx context.Context, name string, id sources.JobID, sourceID sources.SourceID, verify bool, connection *anypb.Any, concurrency int) error {
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
	case *sourcespb.GCS_Oauth:
		client, err := oauth2Client(aCtx, conn.GetOauth())
		if err != nil {
			return nil, fmt.Errorf("error creating oauth2 client: %w", err)
		}
		gcsManagerAuthOption = withHTTPClient(aCtx, client)
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

func oauth2Client(ctx context.Context, creds *credentialspb.Oauth2) (*http.Client, error) {
	if creds == nil {
		return nil, fmt.Errorf("oauth2 credentials are required")
	}
	if creds.GetClientId() == "" || creds.GetRefreshToken() == "" || creds.GetAccessToken() == "" {
		return nil, fmt.Errorf("oauth2 credentials are incomplete, client_id, refresh_token, and access_token are required")
	}

	conf := &oauth2.Config{
		ClientID: creds.GetClientId(),
		Scopes:   []string{storage.ScopeReadOnly},
		Endpoint: oauth2.Endpoint{
			AuthURL:  endpoints.Google.AuthURL,
			TokenURL: endpoints.Google.TokenURL,
		},
	}

	tok := &oauth2.Token{
		AccessToken:  creds.GetAccessToken(),
		RefreshToken: creds.GetRefreshToken(),
	}

	return conf.Client(ctx, tok), nil
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

// enumerate all the objects and buckets in the source.
// This will be used to calculate progress.
func (s *Source) enumerate(ctx context.Context) error {
	stats, err := s.gcsManager.Attributes(ctx)
	if err != nil {
		return fmt.Errorf("error getting attributes during enumeration: %w", err)
	}
	s.stats = stats

	return nil
}

// Chunks emits chunks of bytes over a channel.
func (s *Source) Chunks(ctx context.Context, chunksChan chan *sources.Chunk, _ ...sources.ChunkingTarget) error {
	persistableCache := s.setupCache(ctx)

	objectCh, err := s.gcsManager.ListObjects(ctx)
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

		if persistableCache.Exists(o.md5) {
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
			s.setProgress(ctx, o.md5, o.name, persistableCache)
		}(o)
	}
	wg.Wait()

	s.completeProgress(ctx)
	return nil
}

func (s *Source) setupCache(ctx context.Context) *persistableCache {
	var c cache.Cache
	if s.Progress.EncodedResumeInfo != "" {
		keys := strings.Split(s.Progress.EncodedResumeInfo, ",")
		entries := make([]memory.CacheEntry, len(keys))
		for i, val := range keys {
			entries[i] = memory.CacheEntry{Key: val, Value: val}
		}

		c = memory.NewWithData(entries)
		ctx.Logger().V(3).Info("Loaded cache", "num_entries", len(entries))
	} else {
		c = memory.New()
	}

	// TODO (ahrav): Make this configurable via conn.
	persistCache := newPersistableCache(defaultCachePersistIncrement, c, &s.Progress)
	return persistCache
}

func (s *Source) setProgress(ctx context.Context, md5, objName string, cache cache.Cache) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ctx.Logger().V(5).Info("setting progress for object", "object-name", objName)
	s.SectionsCompleted++

	cache.Set(md5, md5)
	s.Progress.SectionsRemaining = int32(s.stats.numObjects)
	s.Progress.PercentComplete = int64(float64(s.SectionsCompleted) / float64(s.stats.numObjects) * 100)
}

func (s *Source) completeProgress(ctx context.Context) {
	msg := fmt.Sprintf("GCS source finished processing %d objects", s.stats.numObjects)
	ctx.Logger().Info(msg)
	s.Progress.Message = msg
}

func (s *Source) processObject(ctx context.Context, o object) error {
	chunkSkel := &sources.Chunk{
		SourceName: s.name,
		SourceType: s.Type(),
		JobID:      s.JobID(),
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
					CreatedAt:   strconv.FormatInt(o.createdAt.Unix(), 10), // Unix time as string
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
	bufferName := cleantemp.MkFilename()
	reader, err := diskbufferreader.New(o, diskbufferreader.WithBufferName(bufferName))
	if err != nil {
		return nil, fmt.Errorf("error creating disk buffer reader: %w", err)
	}
	defer reader.Close()

	if handlers.HandleFile(ctx, reader, chunk, sources.ChanReporter{Ch: s.chunksCh}) {
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
