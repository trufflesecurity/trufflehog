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
	return nil
}
