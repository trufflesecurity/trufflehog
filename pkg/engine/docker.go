package engine

import (
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/docker"
)

// ScanDocker scans a given docker connection.
func (e *Engine) ScanDocker(ctx context.Context, conn *anypb.Any) error {
	sourceName := "trufflehog - docker"
	sourceID, jobID, _ := e.sourceManager.GetIDs(ctx, sourceName, docker.SourceType)

	src := &docker.Source{}
	err := src.Init(
		ctx,
		sources.NewConfig(
			conn,
			sources.WithName(sourceName),
			sources.WithSourceID(sourceID),
			sources.WithJobID(jobID),
			sources.WithVerify(e.verify),
			sources.WithConcurrency(int(e.concurrency)),
		),
	)
	if err != nil {
		return err
	}

	_, err = e.sourceManager.Run(ctx, sourceName, src)
	return err
}
