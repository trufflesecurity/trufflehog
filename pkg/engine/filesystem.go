package engine

import (
	"runtime"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/filesystem"
)

// ScanFileSystem scans a given file system.
func (e *Engine) ScanFileSystem(ctx context.Context, c sources.FilesystemConfig) (sources.JobProgressRef, error) {
	connection := &sourcespb.Filesystem{
		Paths:            c.Paths,
		IncludePathsFile: c.IncludePathsFile,
		ExcludePathsFile: c.ExcludePathsFile,
		MaxSymlinkDepth:  c.MaxSymlinkDepth,
	}
	var conn anypb.Any
	err := anypb.MarshalFrom(&conn, connection, proto.MarshalOptions{})
	if err != nil {
		ctx.Logger().Error(err, "failed to marshal filesystem connection")
		return sources.JobProgressRef{}, err
	}

	sourceName := "trufflehog - filesystem"
	sourceID, jobID, _ := e.sourceManager.GetIDs(ctx, sourceName, filesystem.SourceType)

	fileSystemSource := &filesystem.Source{}
	if err := fileSystemSource.Init(ctx, sourceName, jobID, sourceID, true, &conn, runtime.NumCPU()); err != nil {
		return sources.JobProgressRef{}, err
	}
	return e.sourceManager.EnumerateAndScan(ctx, sourceName, fileSystemSource)
}
