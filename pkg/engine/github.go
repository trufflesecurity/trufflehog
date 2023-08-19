package engine

import (
	gogit "github.com/go-git/go-git/v5"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/git"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/github"
)

// ScanGitHub scans Github with the provided options.
func (e *Engine) ScanGitHub(ctx context.Context, c sources.GithubConfig) error {
	connection := sourcespb.GitHub{
		Endpoint:                   c.Endpoint,
		Organizations:              c.Orgs,
		Repositories:               c.Repos,
		ScanUsers:                  c.IncludeMembers,
		IgnoreRepos:                c.ExcludeRepos,
		IncludeRepos:               c.IncludeRepos,
		IncludeIssueComments:       c.IncludeIssueComments,
		IncludePullRequestComments: c.IncludePullRequestComments,
		IncludeGistComments:        c.IncludeGistComments,
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

	logOptions := &gogit.LogOptions{}
	opts := []git.ScanOption{
		git.ScanOptionFilter(c.Filter),
		git.ScanOptionLogOptions(logOptions),
	}
	scanOptions := git.NewScanOptions(opts...)

	handle, err := e.sourceManager.Enroll(ctx, "trufflehog - github", new(github.Source).Type(),
		func(ctx context.Context, jobID, sourceID int64) (sources.Source, error) {
			githubSource := github.Source{}
			if err := githubSource.Init(ctx, "trufflehog - github", jobID, sourceID, true, &conn, c.Concurrency); err != nil {
				return nil, err
			}
			githubSource.WithScanOptions(scanOptions)
			return &githubSource, nil
		})
	if err != nil {
		return err
	}
	_, err = e.sourceManager.ScheduleRun(ctx, handle)
	return err
}
