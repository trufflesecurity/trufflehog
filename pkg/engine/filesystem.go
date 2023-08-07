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
func (e *Engine) ScanFileSystem(ctx context.Context, c sources.FilesystemConfig) error {
	connection := &sourcespb.Filesystem{
		Paths: c.Paths,
	}
	var conn anypb.Any
	err := anypb.MarshalFrom(&conn, connection, proto.MarshalOptions{})
	if err != nil {
		ctx.Logger().Error(err, "failed to marshal filesystem connection")
		return err
	}

	handle, err := e.sourceManager.Enroll(ctx, "trufflehog - filesystem", new(filesystem.Source).Type(),
		func(ctx context.Context, jobID, sourceID int64) (sources.Source, error) {
			fileSystemSource := filesystem.Source{}
			fileSystemSource.WithFilter(c.Filter)
			if err := fileSystemSource.Init(ctx, "trufflehog - filesystem", jobID, sourceID, true, &conn, runtime.NumCPU()); err != nil {
				return nil, err
			}
			return &fileSystemSource, nil
		})
	if err != nil {
		return err
	}
	_, err = e.sourceManager.ScheduleRun(ctx, handle)
	return err
}
