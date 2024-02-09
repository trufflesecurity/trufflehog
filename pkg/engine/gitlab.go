package engine

import (
	"fmt"

	gogit "github.com/go-git/go-git/v5"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/git"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/gitlab"
)

// ScanGitLab scans GitLab with the provided configuration.
func (e *Engine) ScanGitLab(ctx context.Context, c sources.GitlabConfig) error {
	connection := &sourcespb.GitLab{SkipBinaries: c.SkipBinaries}

	switch {
	case len(c.Token) > 0:
		connection.Credential = &sourcespb.GitLab_Token{
			Token: c.Token,
		}
	default:
		return fmt.Errorf("must provide token")
	}

	if len(c.Endpoint) > 0 {
		connection.Endpoint = c.Endpoint
	}

	if len(c.Repos) > 0 {
		connection.Repositories = c.Repos
	}

	var conn anypb.Any
	err := anypb.MarshalFrom(&conn, connection, proto.MarshalOptions{})
	if err != nil {
		ctx.Logger().Error(err, "failed to marshal gitlab connection")
		return err
	}

	sourceName := "trufflehog - gitlab"
	sourceID, jobID, _ := e.sourceManager.GetIDs(ctx, sourceName, gitlab.SourceType)

	src := &gitlab.Source{}
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

	logOptions := &gogit.LogOptions{}
	opts := []git.ScanOption{
		git.ScanOptionFilter(c.Filter),
		git.ScanOptionLogOptions(logOptions),
	}
	scanOptions := git.NewScanOptions(opts...)
	src.WithScanOptions(scanOptions)

	_, err = e.sourceManager.Run(ctx, sourceName, src)
	return err
}
