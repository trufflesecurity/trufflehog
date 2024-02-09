package engine

import (
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

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

	sourceName := "trufflehog - Circle CI"
	sourceID, jobID, _ := e.sourceManager.GetIDs(ctx, sourceName, circleci.SourceType)

	src := &circleci.Source{}
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
