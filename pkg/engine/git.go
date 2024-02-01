package engine

import (
	"runtime"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/git"
)

// ScanGit scans any git source.
func (e *Engine) ScanGit(ctx context.Context, c sources.GitConfig) error {
	connection := &sourcespb.Git{
		Head:             c.HeadRef,
		Base:             c.BaseRef,
		Bare:             c.Bare,
		Uri:              c.URI,
		ExcludeGlobs:     c.ExcludeGlobs,
		IncludePathsFile: c.IncludePathsFile,
		ExcludePathsFile: c.ExcludePathsFile,
		MaxDepth:         int64(c.MaxDepth),
		SkipBinaries:     c.SkipBinaries,
	}
	var conn anypb.Any
	if err := anypb.MarshalFrom(&conn, connection, proto.MarshalOptions{}); err != nil {
		ctx.Logger().Error(err, "failed to marshal git connection")
		return err
	}

	sourceName := "trufflehog - git"
	sourceID, jobID, _ := e.sourceManager.GetIDs(ctx, sourceName, git.SourceType)

	gitSource := &git.Source{}
	if err := gitSource.Init(ctx, sourceName, jobID, sourceID, true, &conn, runtime.NumCPU()); err != nil {
		return err
	}

	_, err := e.sourceManager.Run(ctx, sourceName, gitSource)
	return err
}
