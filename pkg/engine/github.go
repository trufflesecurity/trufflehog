package engine

import (
	"context"

	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/github"
)

func (e *Engine) ScanGitHub(ctx context.Context, endpoint string, repos, orgs []string, token string, includeForks bool, filter *common.Filter, concurrency int, includeMembers bool) error {
	source := github.Source{}
	connection := sourcespb.GitHub{
		Endpoint:      endpoint,
		Organizations: orgs,
		Repositories:  repos,
		ScanUsers:     includeMembers,
	}
	if len(token) > 0 {
		connection.Credential = &sourcespb.GitHub_Token{
			Token: token,
		}
	} else {
		connection.Credential = &sourcespb.GitHub_Unauthenticated{}
	}
	connection.IncludeForks = includeForks
	var conn anypb.Any
	err := anypb.MarshalFrom(&conn, &connection, proto.MarshalOptions{})
	if err != nil {
		logrus.WithError(err).Error("failed to marshal github connection")
		return err
	}
	err = source.Init(ctx, "trufflehog - github", 0, 0, false, &conn, concurrency)
	if err != nil {
		logrus.WithError(err).Error("failed to initialize github source")
		return err
	}

	e.sourcesWg.Add(1)
	go func() {
		defer e.sourcesWg.Done()
		err := source.Chunks(ctx, e.ChunksChan())
		if err != nil {
			logrus.WithError(err).Fatal("could not scan github")
		}
	}()
	return nil
}
