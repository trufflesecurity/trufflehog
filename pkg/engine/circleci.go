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
	ctx = context.WithValues(ctx,
		"source_type", circleSource.Type().String(),
		"source_name", "Circle CI",
	)
	err = circleSource.Init(ctx, "trufflehog - Circle CI", 0, int64(sourcespb.SourceType_SOURCE_TYPE_CIRCLECI), true, &conn, runtime.NumCPU())
	if err != nil {
		return errors.WrapPrefix(err, "failed to init Circle CI source", 0)
	}

	e.sourcesWg.Go(func() error {
		defer common.RecoverWithExit(ctx)
		err := circleSource.Chunks(ctx, e.ChunksChan())
		if err != nil {
			return fmt.Errorf("error scanning CircleCI: %w", err)
		}
		return nil
	})
	return nil
}
