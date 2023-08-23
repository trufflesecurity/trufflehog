package engine

import (
	"runtime"

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

	handle, err := e.sourceManager.Enroll(ctx, "trufflehog - Circle CI", new(circleci.Source).Type(),
		func(ctx context.Context, jobID, sourceID int64) (sources.Source, error) {
			circleSource := circleci.Source{}
			if err := circleSource.Init(ctx, "trufflehog - Circle CI", jobID, sourceID, true, &conn, runtime.NumCPU()); err != nil {
				return nil, err
			}
			return &circleSource, nil
		})
	if err != nil {
		return err
	}
	_, err = e.sourceManager.ScheduleRun(ctx, handle)
	return err
}
