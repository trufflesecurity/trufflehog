package engine

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/decoders"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/defaults"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

func TestNewDockerSourceHonoursEngineConcurrency(t *testing.T) {
	ctx, cancel := context.WithCancel(context.TODO())
	defer cancel()

	// Pick a configured concurrency that differs from the visible CPU count,
	// so a source initialised with runtime.NumCPU() fails this test.
	configured := 2
	if runtime.NumCPU() == configured {
		configured = 3
	}

	sourceManager := sources.NewManager(
		sources.WithSourceUnits(),
		sources.WithBufferedOutput(64),
	)

	conf := Config{
		Concurrency:   configured,
		Decoders:      decoders.DefaultDecoders(),
		Detectors:     defaults.DefaultDetectors(),
		Verify:        false,
		SourceManager: sourceManager,
		Dispatcher:    NewPrinterDispatcher(new(discardPrinter)),
	}

	e, err := NewEngine(ctx, &conf)
	assert.NoError(t, err)

	connection := &sourcespb.Docker{
		Images:     []string{"example.com/test:latest"},
		Credential: &sourcespb.Docker_Unauthenticated{},
	}
	var conn anypb.Any
	assert.NoError(t, conn.MarshalFrom(connection))

	src, err := e.newDockerSource(ctx, "trufflehog - docker", 0, 0, &conn)
	assert.NoError(t, err)
	assert.Equal(t, configured, src.Concurrency())
}

func TestNewDockerSourceDefaultsToNumCPU(t *testing.T) {
	ctx, cancel := context.WithCancel(context.TODO())
	defer cancel()

	sourceManager := sources.NewManager(
		sources.WithSourceUnits(),
		sources.WithBufferedOutput(64),
	)

	conf := Config{
		Decoders:      decoders.DefaultDecoders(),
		Detectors:     defaults.DefaultDetectors(),
		Verify:        false,
		SourceManager: sourceManager,
		Dispatcher:    NewPrinterDispatcher(new(discardPrinter)),
	}

	e, err := NewEngine(ctx, &conf)
	assert.NoError(t, err)

	connection := &sourcespb.Docker{
		Images:     []string{"example.com/test:latest"},
		Credential: &sourcespb.Docker_Unauthenticated{},
	}
	var conn anypb.Any
	assert.NoError(t, conn.MarshalFrom(connection))

	src, err := e.newDockerSource(ctx, "trufflehog - docker", 0, 0, &conn)
	assert.NoError(t, err)
	assert.Equal(t, runtime.NumCPU(), src.Concurrency())
}
