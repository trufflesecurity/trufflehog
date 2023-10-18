package engine

import (
	"runtime"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/travisci"
)

// ScanTravisCI scans TravisCI logs.
func (e *Engine) ScanTravisCI(ctx context.Context, token string) error {
	connection := &sourcespb.TravisCI{
		Credential: &sourcespb.TravisCI_Token{
			Token: token,
		},
	}

	var conn anypb.Any
	err := anypb.MarshalFrom(&conn, connection, proto.MarshalOptions{})
	if err != nil {
		ctx.Logger().Error(err, "failed to marshal Travis CI connection")
		return err
	}

	sourceName := "trufflehog - Travis CI"
	sourceID, jobID, _ := e.sourceManager.GetIDs(ctx, sourceName, travisci.SourceType)

	travisSource := &travisci.Source{}
	if err := travisSource.Init(ctx, sourceName, jobID, sourceID, true, &conn, runtime.NumCPU()); err != nil {
		return err
	}
	_, err = e.sourceManager.Run(ctx, sourceName, travisSource)
	return err
}
