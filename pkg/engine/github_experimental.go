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
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/github"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/github_experimental"
)

// ScanGitHubExperimental scans GitHub using an experimental feature. Consider all functionality to be in an alpha release here.
func (e *Engine) ScanGitHubExperimental(ctx context.Context, c sources.GitHubExperimentalConfig) error {
	connection := sourcespb.GitHubExperimental{
		Repository:         c.Repository,
		ObjectDiscovery:    c.ObjectDiscovery,
		CollisionThreshold: int64(c.CollisionThreshold),
		DeleteCachedData:   c.DeleteCachedData,
	}

	// Check at least one experimental sub-module is being used.
	// Add to this list as more experimental sub-modules are added.
	if !c.ObjectDiscovery {
		return fmt.Errorf("at least one experimental submodule must be enabled")
	}

	if len(c.Token) > 0 {
		connection.Credential = &sourcespb.GitHubExperimental_Token{
			Token: c.Token,
		}
	} else {
		return fmt.Errorf("token is required for github experimental")
	}

	var conn anypb.Any
	err := anypb.MarshalFrom(&conn, &connection, proto.MarshalOptions{})
	if err != nil {
		ctx.Logger().Error(err, "failed to marshal github experimental connection")
		return err
	}

	logOptions := &gogit.LogOptions{}
	opts := []git.ScanOption{
		git.ScanOptionLogOptions(logOptions),
	}
	scanOptions := git.NewScanOptions(opts...)

	sourceName := "trufflehog - github experimental (alpha release)"
	sourceID, jobID, _ := e.sourceManager.GetIDs(ctx, sourceName, github.SourceType)

	githubExperimentalSource := &github_experimental.Source{}
	if err := githubExperimentalSource.Init(ctx, sourceName, jobID, sourceID, true, &conn, runtime.NumCPU()); err != nil {
		return err
	}
	githubExperimentalSource.WithScanOptions(scanOptions)
	_, err = e.sourceManager.Run(ctx, sourceName, githubExperimentalSource)
	return err
}
