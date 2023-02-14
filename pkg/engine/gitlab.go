package engine

import (
	"fmt"
	"runtime"

	"github.com/go-errors/errors"
	gogit "github.com/go-git/go-git/v5"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/git"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/gitlab"
)

// ScanGitLab scans GitLab with the provided configuration.
func (e *Engine) ScanGitLab(ctx context.Context, c sources.GitlabConfig) error {
	logOptions := &gogit.LogOptions{}
	opts := []git.ScanOption{
		git.ScanOptionFilter(c.Filter),
		git.ScanOptionLogOptions(logOptions),
	}
	scanOptions := git.NewScanOptions(opts...)

	connection := &sourcespb.GitLab{}

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

	gitlabSource := gitlab.Source{}
	ctx = context.WithValues(ctx,
		"source_type", gitlabSource.Type().String(),
		"source_name", "gitlab",
	)
	err = gitlabSource.Init(ctx, "trufflehog - gitlab", 0, int64(sourcespb.SourceType_SOURCE_TYPE_GITLAB), true, &conn, runtime.NumCPU())
	if err != nil {
		return errors.WrapPrefix(err, "could not init GitLab source", 0)
	}
	gitlabSource.WithScanOptions(scanOptions)

	e.sourcesWg.Add(1)
	go func() {
		defer common.RecoverWithExit(ctx)
		defer e.sourcesWg.Done()
		err := gitlabSource.Chunks(ctx, e.ChunksChan())
		if err != nil {
			ctx.Logger().Error(err, "error scanning GitLab")
		}
	}()
	return nil
}
