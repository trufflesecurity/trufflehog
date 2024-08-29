package engine

import (
	"strings"

	gogit "github.com/go-git/go-git/v5"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/git"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/github"
)

// ScanGitHub scans GitHub with the provided options.
func (e *Engine) ScanGitHub(ctx context.Context, c sources.GithubConfig) error {
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
		return err
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
		return err
	}
	githubSource.WithScanOptions(scanOptions)

	if c.Target != "" {
		parts := strings.Split(c.Target, "@")
		target := sources.ChunkingTarget{
			QueryCriteria: &source_metadatapb.MetaData{
				Data: &source_metadatapb.MetaData_Github{
					Github: &source_metadatapb.Github{
						Link:   c.Repos[0],
						File:   parts[0],
						Commit: parts[1],
					},
				},
			},
		}
		_, err = e.sourceManager.Run(ctx, sourceName, githubSource, target)
		return err
	}

	_, err = e.sourceManager.Run(ctx, sourceName, githubSource)
	return err
}
