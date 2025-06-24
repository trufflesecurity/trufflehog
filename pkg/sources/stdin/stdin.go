package stdin

import (
	"os"

	"github.com/go-logr/logr"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/handlers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

const SourceType = sourcespb.SourceType_SOURCE_TYPE_STDIN

type Source struct {
	name     string
	sourceId sources.SourceID
	jobId    sources.JobID
	verify   bool
	log      logr.Logger
	sources.Progress
	sources.CommonSourceUnitUnmarshaller
}

var _ sources.Source = (*Source)(nil)
var _ sources.SourceUnitUnmarshaller = (*Source)(nil)
var _ sources.SourceUnitEnumChunker = (*Source)(nil)

func (s *Source) Type() sourcespb.SourceType {
	return SourceType
}

func (s *Source) SourceID() sources.SourceID {
	return s.sourceId
}

func (s *Source) JobID() sources.JobID {
	return s.jobId
}

func (s *Source) Init(aCtx context.Context, name string, jobId sources.JobID, sourceId sources.SourceID, verify bool, _ *anypb.Any, _ int) error {
	s.name = name
	s.jobId = jobId
	s.sourceId = sourceId
	s.verify = verify
	s.log = aCtx.Logger()
	return nil
}

func (s *Source) Chunks(ctx context.Context, chunksChan chan *sources.Chunk, _ ...sources.ChunkingTarget) error {
	stdin := os.Stdin
	chunkSkel := &sources.Chunk{
		SourceType: s.Type(),
		SourceName: s.name,
		SourceID:   s.SourceID(),
		JobID:      s.JobID(),
		SourceMetadata: &source_metadatapb.MetaData{
			Data: &source_metadatapb.MetaData_Stdin{},
		},
		Verify: s.verify,
	}

	ctx.Logger().Info("scanning stdin for secrets")
	return handlers.HandleFile(ctx, stdin, chunkSkel, sources.ChanReporter{Ch: chunksChan})
}

func (s *Source) Enumerate(ctx context.Context, reporter sources.UnitReporter) error {
	unit := sources.CommonSourceUnit{ID: "<stdin>"}
	return reporter.UnitOk(ctx, unit)
}

func (s *Source) ChunkUnit(ctx context.Context, unit sources.SourceUnit, reporter sources.ChunkReporter) error {
	ch := make(chan *sources.Chunk)
	go func() {
		defer close(ch)
		_ = s.Chunks(ctx, ch)
	}()
	for chunk := range ch {
		if chunk != nil {
			if err := reporter.ChunkOk(ctx, *chunk); err != nil {
				return err
			}
		}
	}
	return nil
}
