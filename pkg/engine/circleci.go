package engine

import (
	"runtime"

	"github.com/go-errors/errors"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/circleci"
)

// ScanCircleCI scans CircleCI logs.
func (e *Engine) ScanCircleCI(ctx context.Context, token string) error {
	connection := &sourcespb.CircleCI{
		Credential: &sourcespb.CircleCI_Token{
			Token: token,
		},
	}

	var conn anypb.Any
	err := anypb.MarshalFrom(&conn, connection, proto.MarshalOptions{})
	if err != nil {
		ctx.Logger().Error(err, "failed to marshal Circle CI connection")
		return err
	}

	circleSource := circleci.Source{}
	cfg := sources.NewSourceConfig(
		"trufflehog - Circle CI",
		0,
		int64(sourcespb.SourceType_SOURCE_TYPE_CIRCLECI),
		&conn,
		sources.WithConcurrency(runtime.NumCPU()),
		sources.WithVerify(true),
	)
	ctx = context.WithValues(ctx,
		"source_type", circleSource.Type().String(),
		"source_name", "Circle CI",
	)
	err = circleSource.Init(ctx, cfg)
	if err != nil {
		return errors.WrapPrefix(err, "failed to init Circle CI source", 0)
	}

	e.sourcesWg.Add(1)
	go func() {
		defer common.RecoverWithExit(ctx)
		defer e.sourcesWg.Done()
		err := circleSource.Chunks(ctx, e.ChunksChan())
		if err != nil {
			ctx.Logger().Error(err, "error scanning Circle CI")
		}
	}()
	return nil
}
