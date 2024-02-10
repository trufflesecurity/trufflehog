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

// VisitorReporter is a UnitReporter that will call the provided callbacks for
// finding units and reporting errors. VisitErr is optional; if unset it will
// log the error.
type VisitorReporter struct {
	VisitUnit func(context.Context, SourceUnit) error
	VisitErr  func(context.Context, error) error
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
