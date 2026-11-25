package engine

import (
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
		Images:        c.Images,
		ExcludePaths:  c.ExcludePaths,
		Namespace:     c.Namespace,
		RegistryToken: c.RegistryToken,
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
	ctx = withSourceFields(ctx, sourceName, docker.SourceType, sourceID, jobID)

	dockerSource, err := e.newDockerSource(ctx, sourceName, jobID, sourceID, &conn)
	if err != nil {
		return sources.JobProgressRef{}, err
	}
	return e.sourceManager.EnumerateAndScan(ctx, sourceName, dockerSource)
}

// newDockerSource builds the docker source for a scan. It passes the engine's
// configured concurrency through, so --concurrency caps how many layers are
// scanned at once (each holding 128 MiB of gzip read-ahead) instead of the
// number of CPUs visible to the process.
func (e *Engine) newDockerSource(ctx context.Context, sourceName string, jobID sources.JobID, sourceID sources.SourceID, conn *anypb.Any) (*docker.Source, error) {
	dockerSource := &docker.Source{}
	if err := dockerSource.Init(ctx, sourceName, jobID, sourceID, true, conn, e.concurrency); err != nil {
		return nil, err
	}
	return dockerSource, nil
}
