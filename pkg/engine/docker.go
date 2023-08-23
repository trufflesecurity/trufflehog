package engine

import (
	"runtime"

	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/docker"
)

// ScanDocker scans a given docker connection.
func (e *Engine) ScanDocker(ctx context.Context, conn *anypb.Any) error {
	handle, err := e.sourceManager.Enroll(ctx, "trufflehog - docker", new(docker.Source).Type(),
		func(ctx context.Context, jobID, sourceID int64) (sources.Source, error) {
			dockerSource := docker.Source{}
			if err := dockerSource.Init(ctx, "trufflehog - docker", jobID, sourceID, true, conn, runtime.NumCPU()); err != nil {
				return nil, err
			}
			return &dockerSource, nil
		})
	if err != nil {
		return err
	}
	_, err = e.sourceManager.ScheduleRun(ctx, handle)
	return err
}
