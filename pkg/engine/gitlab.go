package engine

import (
	"fmt"
	"runtime"

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
func (e *Engine) ScanGitLab(ctx context.Context, c sources.GitlabConfig) (sources.JobProgressRef, error) {
	logOptions := &gogit.LogOptions{}
	opts := []git.ScanOption{
		git.ScanOptionFilter(c.Filter),
		git.ScanOptionLogOptions(logOptions),
	}
	scanOptions := git.NewScanOptions(opts...)

	connection := &sourcespb.GitLab{
		SkipBinaries:    c.SkipBinaries,
		RemoveAuthInUrl: !c.AuthInUrl, // configuration uses the opposite field in proto to keep credentials in the URL by default.
	}

	switch {
	case len(c.Token) > 0:
		connection.Credential = &sourcespb.GitLab_Token{
			Token: c.Token,
		}
	default:
		return sources.JobProgressRef{}, fmt.Errorf("must provide token")
	}

	if len(c.Endpoint) > 0 {
		connection.Endpoint = c.Endpoint
	}

	if len(c.Repos) > 0 {
		connection.Repositories = c.Repos
	}

	if len(c.IncludeRepos) > 0 {
		connection.IncludeRepos = c.IncludeRepos
	}

	if len(c.ExcludeRepos) > 0 {
		connection.IgnoreRepos = c.ExcludeRepos
	}

	var conn anypb.Any
	err := anypb.MarshalFrom(&conn, connection, proto.MarshalOptions{})
	if err != nil {
		ctx.Logger().Error(err, "failed to marshal gitlab connection")
		return sources.JobProgressRef{}, err
	}

	sourceName := "trufflehog - gitlab"
	sourceID, jobID, _ := e.sourceManager.GetIDs(ctx, sourceName, gitlab.SourceType)

	gitlabSource := &gitlab.Source{}
	if err := gitlabSource.Init(ctx, sourceName, jobID, sourceID, true, &conn, runtime.NumCPU()); err != nil {
		return sources.JobProgressRef{}, err
	}
	gitlabSource.WithScanOptions(scanOptions)
	return e.sourceManager.EnumerateAndScan(ctx, sourceName, gitlabSource)
}
