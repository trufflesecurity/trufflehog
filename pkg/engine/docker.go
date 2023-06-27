package engine

import (
	"fmt"
	"runtime"

	"github.com/go-errors/errors"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/docker"
)

// ScanDocker scans a given docker connection.
func (e *Engine) ScanDocker(ctx context.Context, conn *anypb.Any) error {
	dockerSource := docker.Source{}

	ctx = context.WithValues(ctx,
		"source_type", dockerSource.Type().String(),
		"source_name", "docker",
	)
	err := dockerSource.Init(ctx, "trufflehog - docker", 0, int64(sourcespb.SourceType_SOURCE_TYPE_DOCKER), true, conn, runtime.NumCPU())
	if err != nil {
		return errors.WrapPrefix(err, "could not init docker source", 0)
	}

	e.sourcesWg.Go(func() error {
		defer common.RecoverWithExit(ctx)
		err := dockerSource.Chunks(ctx, e.ChunksChan())
		if err != nil {
			return fmt.Errorf("error scanning docker image: %w", err)
		}
		return nil
	})
	return nil
}
