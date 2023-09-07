package engine

import (
	"runtime"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/trello"
)

// ScanTrello scans Trello boards for secrets.
func (e *Engine) ScanTrello(ctx context.Context, apiKey string) error {
	trelloSource := trello.Source{}
	boardIDs, err := trelloSource.GetBoardIDs(ctx, apiKey)
	if err != nil {
		ctx.Logger().Error(err, "failed to get Trello board IDs")
		return err
	}

	connection := &sourcespb.Trello{
		Auth: &sourcespb.Trello_TrelloAuth{
			ApiKey: apiKey,
		},
		Boards: boardIDs,
	}

	var conn anypb.Any
	err = anypb.MarshalFrom(&conn, connection, proto.MarshalOptions{})
	if err != nil {
		ctx.Logger().Error(err, "failed to marshal Trello connection")
		return err
	}

	handle, err := e.sourceManager.Enroll(ctx, "trufflehog - Trello", new(trello.Source).Type(),
		func(ctx context.Context, jobID, sourceID int64) (sources.Source, error) {
			if err := trelloSource.Init(ctx, "trufflehog - Trello", jobID, sourceID, true, &conn, runtime.NumCPU()); err != nil {
				return nil, err
			}
			return &trelloSource, nil
		})
	if err != nil {
		return err
	}
	_, err = e.sourceManager.ScheduleRun(ctx, handle)
	return err
}
