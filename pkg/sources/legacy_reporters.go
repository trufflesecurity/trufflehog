package sources

import (
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

var _ ChunkReporter = (*ChanReporter)(nil)

// ChanReporter is a ChunkReporter that writes to a channel.
type ChanReporter struct {
	Ch chan<- *Chunk
}

func (c ChanReporter) ChunkOk(ctx context.Context, chunk Chunk) error {
	return common.CancellableWrite(ctx, c.Ch, &chunk)
}

func (ChanReporter) ChunkErr(ctx context.Context, err error) error {
	ctx.Logger().Error(err, "error chunking")
	return ctx.Err()
}

var _ UnitReporter = (*VisitorReporter)(nil)
var _ ChunkReporter = (*VisitorReporter)(nil)

// VisitorReporter is a UnitReporter and ChunkReporter that will call the provided callbacks for
// finding units/chunks and reporting errors. VisitErr and VisitChunkErr are optional; if unset it will
// log the error.
type VisitorReporter struct {
	VisitUnit func(context.Context, SourceUnit) error
	VisitErr  func(context.Context, error) error

	VisitChunk    func(context.Context, Chunk) error
	VisitChunkErr func(context.Context, error) error
}

func (v VisitorReporter) UnitOk(ctx context.Context, unit SourceUnit) error {
	return v.VisitUnit(ctx, unit)
}

func (v VisitorReporter) UnitErr(ctx context.Context, err error) error {
	if v.VisitErr == nil {
		ctx.Logger().Error(err, "error enumerating")
		return ctx.Err()
	}
	return v.VisitErr(ctx, err)
}

func (v VisitorReporter) ChunkOk(ctx context.Context, chunk Chunk) error {
	return v.VisitChunk(ctx, chunk)
}

func (v VisitorReporter) ChunkErr(ctx context.Context, err error) error {
	if v.VisitChunkErr == nil {
		ctx.Logger().Error(err, "error chunking")
		return ctx.Err()
	}
	return v.VisitChunkErr(ctx, err)
}
