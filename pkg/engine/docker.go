package engine

import (
	"runtime"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/docker"
)

// ScanDocker scans a given docker connection.
func (e *Engine) ScanDocker(ctx context.Context, c sources.DockerConfig) (sources.JobProgressRef, error) {
	connection := &sourcespb.Docker{
		Images:       c.Images,
		ExcludePaths: c.ExcludePaths,
	}

	switch {
	case c.UseDockerKeychain:
		connection.Credential = &sourcespb.Docker_DockerKeychain{DockerKeychain: true}
	case len(c.BearerToken) > 0:
		connection.Credential = &sourcespb.Docker_BearerToken{BearerToken: c.BearerToken}
	default:
		connection.Credential = &sourcespb.Docker_Unauthenticated{}
	}

	var conn anypb.Any
	err := anypb.MarshalFrom(&conn, connection, proto.MarshalOptions{})
	if err != nil {
		ctx.Logger().Error(err, "failed to marshal gitlab connection")
		return sources.JobProgressRef{}, err
	}

	sourceName := "trufflehog - docker"
	sourceID, jobID, _ := e.sourceManager.GetIDs(ctx, sourceName, docker.SourceType)

	dockerSource := &docker.Source{}
	if err := dockerSource.Init(ctx, sourceName, jobID, sourceID, true, &conn, runtime.NumCPU()); err != nil {
		return sources.JobProgressRef{}, err
	}
	return e.sourceManager.EnumerateAndScan(ctx, sourceName, dockerSource)
}
