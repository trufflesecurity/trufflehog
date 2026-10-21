package engine

import (
	"testing"
	"time"

	"github.com/go-logr/zapr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/decoders"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

// loggingSource is a fake source that writes one info line and one debug line
// from Init and from Chunks, so a test can see which lines were written.
type loggingSource struct {
	name string
	sources.Progress
}

func (s *loggingSource) Type() sourcespb.SourceType { return sourcespb.SourceType_SOURCE_TYPE_FILESYSTEM }
func (s *loggingSource) SourceID() sources.SourceID { return 0 }
func (s *loggingSource) JobID() sources.JobID       { return 0 }

func (s *loggingSource) Init(ctx context.Context, name string, _ sources.JobID, _ sources.SourceID, _ bool, _ *anypb.Any, _ int) error {
	s.name = name
	ctx.Logger().Info("init info", "source", s.name)
	ctx.Logger().V(5).Info("init debug", "source", s.name)
	return nil
}

func (s *loggingSource) Chunks(ctx context.Context, _ chan *sources.Chunk, _ ...sources.ChunkingTarget) error {
	ctx.Logger().Info("chunks info", "source", s.name)
	ctx.Logger().V(5).Info("chunks debug", "source", s.name)
	return nil
}

func TestScanConfig_DebugOnlyForOneSource(t *testing.T) {
	// Capture logs at the normal level (V(0)), like a default trufflehog run.
	core, logs := observer.New(zapcore.InfoLevel)
	ctx := context.WithLogger(context.Background(), zapr.NewLogger(zap.New(core)))
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	e, err := NewEngine(ctx, &Config{
		Concurrency:   1,
		Decoders:      decoders.DefaultDecoders(),
		SourceManager: sources.NewManager(),
		Dispatcher:    NewPrinterDispatcher(new(discardPrinter)),
	})
	require.NoError(t, err)
	e.Start(ctx)

	// One source as in an old config, and one with debug: true.
	normal := sources.NewConfiguredSource(new(loggingSource), &sourcespb.LocalSource{Name: "normal"})
	debug := sources.NewConfiguredSource(new(loggingSource), &sourcespb.LocalSource{Name: "debug", Debug: true})

	_, err = e.ScanConfig(ctx, normal, debug)
	require.NoError(t, err)
	require.NoError(t, e.Finish(ctx))

	// countLines returns how many lines with this message the given source wrote.
	countLines := func(message, source string) int {
		return logs.FilterMessage(message).FilterField(zap.String("source", source)).Len()
	}

	// Both sources write their info lines.
	for _, source := range []string{"normal", "debug"} {
		assert.Equal(t, 1, countLines("init info", source), source)
		assert.Equal(t, 1, countLines("chunks info", source), source)
	}

	// Only the debug source writes debug lines, from both Init and the scan.
	assert.Equal(t, 1, countLines("init debug", "debug"))
	assert.Equal(t, 1, countLines("chunks debug", "debug"))
	assert.Zero(t, countLines("init debug", "normal"))
	assert.Zero(t, countLines("chunks debug", "normal"))
}
