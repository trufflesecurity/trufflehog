package engine

import (
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/github"
)

// ScanGitHub scans Github with the provided options.
func (e *Engine) ScanGitHub(ctx context.Context, c sources.Config) error {
	source := github.Source{}

	connection := sourcespb.GitHub{
		Endpoint:      c.Endpoint,
		Organizations: c.Orgs,
		Repositories:  c.Repos,
		ScanUsers:     c.IncludeMembers,
		IgnoreRepos:   c.ExcludeRepos,
		IncludeRepos:  c.IncludeRepos,
	}
	if len(c.Token) > 0 {
		connection.Credential = &sourcespb.GitHub_Token{
			Token: c.Token,
		}
	} else {
		connection.Credential = &sourcespb.GitHub_Unauthenticated{}
	}
	connection.IncludeForks = c.IncludeForks
	var conn anypb.Any
	err := anypb.MarshalFrom(&conn, &connection, proto.MarshalOptions{})
	if err != nil {
		ctx.Logger().Error(err, "failed to marshal github connection")
		return err
	}

	cfg := sources.NewSourceConfig(
		"trufflehog - github",
		0,
		int64(sourcespb.SourceType_SOURCE_TYPE_GITHUB),
		&conn,
		sources.WithConcurrency(c.Concurrency),
		sources.WithVerify(true),
	)
	err = source.Init(ctx, cfg)
	if err != nil {
		ctx.Logger().Error(err, "failed to initialize github source")
		return err
	}

	e.sourcesWg.Add(1)
	go func() {
		defer common.RecoverWithExit(ctx)
		defer e.sourcesWg.Done()
		err := source.Chunks(ctx, e.ChunksChan())
		if err != nil {
			ctx.Logger().Error(err, "could not scan github")
		}
	}()
	return nil
}
