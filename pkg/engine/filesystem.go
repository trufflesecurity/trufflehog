package engine

import (
	"context"
	"runtime"

	"github.com/go-errors/errors"
	"github.com/sirupsen/logrus"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/filesystem"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

func (e *Engine) ScanFileSystem(ctx context.Context, directories []string) error {
	connection := &sourcespb.Filesystem{
		Directories: directories,
	}
	var conn anypb.Any
	err := anypb.MarshalFrom(&conn, connection, proto.MarshalOptions{})
	if err != nil {
		logrus.WithError(err).Error("failed to marshal filesystem connection")
		return err
	}

	fileSystemSource := filesystem.Source{}
	err = fileSystemSource.Init(ctx, "trufflehog - filesystem", 0, int64(sourcespb.SourceType_SOURCE_TYPE_FILESYSTEM), true, &conn, runtime.NumCPU())
	if err != nil {
		return errors.WrapPrefix(err, "could not init filesystem source", 0)
	}
	e.sourcesWg.Add(1)
	go func() {
		defer e.sourcesWg.Done()
		err := fileSystemSource.Chunks(ctx, e.ChunksChan())
		if err != nil {
			logrus.WithError(err).Error("error scanning filesystem")
		}
	}()
	return nil
}
