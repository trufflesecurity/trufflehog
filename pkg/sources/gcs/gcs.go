package gcs

import (
	"fmt"

	"github.com/go-logr/logr"
	"golang.org/x/sync/errgroup"

	"github.com/go-errors/errors"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
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
	jobPool    *errgroup.Group
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
	s.jobPool = new(errgroup.Group)
	s.jobPool.SetLimit(concurrency)

	var conn sourcespb.GCS
	err := anypb.UnmarshalTo(connection, &conn, proto.UnmarshalOptions{})
	if err != nil {
		return errors.WrapPrefix(err, "error unmarshalling connection", 0)
	}

	gcsMgr, err := newGCSManager(conn.ProjectId,
		withIncludeBuckets(conn.GetIncludeBuckets()),
		withExcludeBuckets(conn.GetExcludeBuckets()),
		withIncludeObjects(conn.GetIncludeObjects()),
		withExcludeObjects(conn.GetExcludeObjects()),
		withConcurrency(concurrency),
	)
	if err != nil {
		return fmt.Errorf("error creating GCS manager: %w", err)
	}
	s.gcsManager = gcsMgr

	return nil
}

// Chunks emits chunks of bytes over a channel.
func (s *Source) Chunks(ctx context.Context, chunksChan chan *sources.Chunk) error {
	objectCh, err := s.gcsManager.listObjects(ctx)
	if err != nil {
		return fmt.Errorf("error listing objects: %w", err)
	}

	s.chunksCh = chunksChan

	for obj := range objectCh {
		o, ok := obj.(object)
		if !ok {
			return fmt.Errorf("error casting object to GCS object")
		}

		if err := s.processObject(ctx, o); err != nil {
			ctx.Logger().V(2).Info("error processing object", "error", err)
		}
	}

	return nil
}

func (s *Source) processObject(ctx context.Context, o object) error {
	meta := &source_metadatapb.MetaData{
		Data: &source_metadatapb.MetaData_Gcs{
			Gcs: &source_metadatapb.GCS{
				Bucket:   o.bucket,
				Filename: o.name,
				Link:     o.link,
				Email:    o.owner,
				// Acl: o.acl,
				CreatedAt: o.createdAt.String(),
				UpdatedAt: o.updatedAt.String(),
			},
		},
	}

	chunk := &sources.Chunk{
		SourceName:     s.name,
		SourceType:     s.Type(),
		SourceID:       s.sourceId,
		Verify:         s.verify,
		SourceMetadata: meta,
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case s.chunksCh <- chunk:
	}

	return nil
}
