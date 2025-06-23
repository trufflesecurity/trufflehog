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

// ScanGitHub scans GitHub with the provided options.
func (e *Engine) ScanGitHub(ctx context.Context, c sources.GithubConfig) (sources.JobProgressRef, error) {
	connection := sourcespb.GitHub{
		Endpoint:                   c.Endpoint,
		Organizations:              c.Orgs,
		Repositories:               c.Repos,
		ScanUsers:                  c.IncludeMembers,
		IgnoreRepos:                c.ExcludeRepos,
		IncludeRepos:               c.IncludeRepos,
		IncludeForks:               c.IncludeForks,
		IncludeIssueComments:       c.IncludeIssueComments,
		IncludePullRequestComments: c.IncludePullRequestComments,
		IncludeGistComments:        c.IncludeGistComments,
		IncludeWikis:               c.IncludeWikis,
		SkipBinaries:               c.SkipBinaries,
		CommentsTimeframeDays:      c.CommentsTimeframeDays,
		RemoveAuthInUrl:            !c.AuthInUrl, // configuration uses the opposite field in proto to keep credentials in the URL by default.
	}
	if len(c.Token) > 0 {
		connection.Credential = &sourcespb.GitHub_Token{
			Token: c.Token,
		}
	} else {
		connection.Credential = &sourcespb.GitHub_Unauthenticated{}
	}

	var conn anypb.Any
	err := anypb.MarshalFrom(&conn, &connection, proto.MarshalOptions{})
	if err != nil {
		ctx.Logger().Error(err, "failed to marshal github connection")
		return sources.JobProgressRef{}, err
	}

	logOptions := &gogit.LogOptions{}
	opts := []git.ScanOption{
		git.ScanOptionFilter(c.Filter),
		git.ScanOptionLogOptions(logOptions),
	}
	scanOptions := git.NewScanOptions(opts...)

	sourceName := "trufflehog - github"
	sourceID, jobID, _ := e.sourceManager.GetIDs(ctx, sourceName, github.SourceType)

	githubSource := &github.Source{}
	if err := githubSource.Init(ctx, sourceName, jobID, sourceID, true, &conn, c.Concurrency); err != nil {
		return sources.JobProgressRef{}, err
	}
	githubSource.WithScanOptions(scanOptions)
	return e.sourceManager.EnumerateAndScan(ctx, sourceName, githubSource)
}
