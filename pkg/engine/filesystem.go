package engine

import (
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/filesystem"
)

// ScanFileSystem scans a given file system.
func (e *Engine) ScanFileSystem(ctx context.Context, c sources.FilesystemConfig) error {
	connection := &sourcespb.Filesystem{
		Paths:            c.Paths,
		IncludePathsFile: c.IncludePathsFile,
		ExcludePathsFile: c.ExcludePathsFile,
	}
	var conn anypb.Any
	err := anypb.MarshalFrom(&conn, connection, proto.MarshalOptions{})
	if err != nil {
		ctx.Logger().Error(err, "failed to marshal filesystem connection")
		return err
	}

	sourceName := "trufflehog - filesystem"
	sourceID, jobID, _ := e.sourceManager.GetIDs(ctx, sourceName, filesystem.SourceType)

	src := &filesystem.Source{}
	err = src.Init(
		ctx,
		sources.NewConfig(
			&conn,
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
