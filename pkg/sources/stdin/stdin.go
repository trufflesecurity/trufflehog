package stdin

import (
	stdctx "context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

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
	aCtx.Logger().V(1).Info("Stdin source initialized", "verify", verify)
	return nil
}

// byteCounter counts the bytes read through it, so the scan can log how much input
// came in. It never looks at the data.
type byteCounter struct {
	r io.Reader
	n int64
}

func (b *byteCounter) Read(p []byte) (int, error) {
	n, err := b.r.Read(p)
	b.n += int64(n)
	return n, err
}

func (s *Source) Chunks(ctx context.Context, chunksChan chan *sources.Chunk, _ ...sources.ChunkingTarget) error {
	stdin := &byteCounter{r: os.Stdin}
	chunkSkel := &sources.Chunk{
		SourceType: s.Type(),
		SourceName: s.name,
		SourceID:   s.SourceID(),
		JobID:      s.JobID(),
		SourceMetadata: &source_metadatapb.MetaData{
			Data: &source_metadatapb.MetaData_Stdin{},
		},
		SourceVerify: s.verify,
	}

	ctx.Logger().Info("scanning stdin for secrets")
	start := time.Now()
	err := handlers.HandleFile(ctx, stdin, chunkSkel, sources.ChanReporter{Ch: chunksChan})
	ctx.Logger().V(1).Info("Finished scanning stdin", "bytes_read", stdin.n, "duration", time.Since(start))
	// HandleFile bounds the whole input by --archive-timeout. A deadline while the scan
	// itself is still running means that limit was hit, so say how to raise it.
	if errors.Is(err, stdctx.DeadlineExceeded) && ctx.Err() == nil {
		return fmt.Errorf("stdin input was not fully scanned: it took longer than the --archive-timeout limit "+
			"(default 60s), raise it with --archive-timeout: %w", err)
	}
	return err
}

func (s *Source) Enumerate(ctx context.Context, reporter sources.UnitReporter) error {
	unit := sources.CommonSourceUnit{ID: "<stdin>"}
	return reporter.UnitOk(ctx, unit)
}

func (s *Source) ChunkUnit(ctx context.Context, unit sources.SourceUnit, reporter sources.ChunkReporter) error {
	ch := make(chan *sources.Chunk)
	var chunksErr error
	go func() {
		defer close(ch)
		chunksErr = s.Chunks(ctx, ch)
	}()
	for chunk := range ch {
		if chunk != nil {
			if err := reporter.ChunkOk(ctx, *chunk); err != nil {
				return err
			}
		}
	}
	// ch is closed only after Chunks returns, so chunksErr is set by now. It is
	// reported as a scan error, not returned, so it fails the run only with
	// --fail-on-scan-errors, like a failed unit in other sources.
	if chunksErr != nil {
		return reporter.ChunkErr(ctx, chunksErr)
	}
	return nil
}
