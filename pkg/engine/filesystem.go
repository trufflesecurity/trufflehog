package engine

import (
	"fmt"
	"runtime"

	"github.com/go-errors/errors"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
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

	fileSystemSource := filesystem.Source{}
	fileSystemSource.WithFilter(c.Filter)

	// TODO: This is how it would be used; everything after these comments would be removed.
	// handle, err := e.sourceManager.Enroll(ctx, "trufflehog - filesystem", fileSystemSource.Type(),
	// 	func(ctx context.Context, jobID, sourceID int64) (sources.Source, error) {
	// 		fileSystemSource := filesystem.Source{}
	// 		fileSystemSource.WithFilter(c.Filter)
	// 		if err := fileSystemSource.Init(ctx, "trufflehog - filesystem", jobID, sourceID, true, &conn, runtime.NumCPU()); err != nil {
	// 			return nil, err
	// 		}
	// 		return &fileSystemSource, nil
	// 	})
	// if err != nil {
	// 	return err
	// }
	// return e.sourceManager.ScheduleRun(ctx, handle)

	ctx = context.WithValues(ctx,
		"source_type", fileSystemSource.Type().String(),
		"source_name", "filesystem",
	)
	err = fileSystemSource.Init(ctx, "trufflehog - filesystem", 0, int64(sourcespb.SourceType_SOURCE_TYPE_FILESYSTEM), true, &conn, runtime.NumCPU())
	if err != nil {
		return errors.WrapPrefix(err, "could not init filesystem source", 0)
	}
	e.sourcesWg.Go(func() error {
		defer common.RecoverWithExit(ctx)
		err := fileSystemSource.Chunks(ctx, e.ChunksChan())
		if err != nil {
			return fmt.Errorf("error scanning filesystem: %w", err)
		}
		return nil
	})
	return nil
}
