package engine

import (
	"runtime"

	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/docker"
)

// ScanDocker scans a given docker connection.
func (e *Engine) ScanDocker(ctx context.Context, conn *anypb.Any) error {
	sourceName := "trufflehog - docker"
	sourceID, jobID, _ := e.sourceManager.GetIDs(ctx, sourceName, docker.SourceType)

	dockerSource := &docker.Source{}
	if err := dockerSource.Init(ctx, sourceName, jobID, sourceID, true, conn, runtime.NumCPU()); err != nil {
		return err
	}
	_, err := e.sourceManager.Run(ctx, sourceName, dockerSource)
	return err
}
