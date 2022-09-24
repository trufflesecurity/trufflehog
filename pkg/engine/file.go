package engine

import (
	"runtime"

	"github.com/go-errors/errors"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/file"
)

// ScanFile scans a given file.
func (e *Engine) ScanFile(ctx context.Context, c sources.Config) error {
	connection := &sourcespb.File{
		Path: c.FilePath,
	}
	var conn anypb.Any
	err := anypb.MarshalFrom(&conn, connection, proto.MarshalOptions{})
	if err != nil {
		logrus.WithError(err).Error("failed to marshal file connection")
		return err
	}

	fileSrc := file.Source{}
	err = fileSrc.Init(ctx, "trufflehog - file", 0, int64(sourcespb.SourceType_SOURCE_TYPE_FILE), true, &conn, runtime.NumCPU())
	if err != nil {
		return errors.WrapPrefix(err, "could not init file source", 0)
	}
	e.sourcesWg.Add(1)
	go func() {
		defer common.RecoverWithExit(ctx)
		defer e.sourcesWg.Done()
		err := fileSrc.Chunks(ctx, e.ChunksChan())
		if err != nil {
			logrus.WithError(err).Error("error scanning file")
		}
	}()
	return nil
}
