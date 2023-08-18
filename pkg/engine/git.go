package engine

import (
	"runtime"

	gogit "github.com/go-git/go-git/v5"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/git"
)

// ScanGit scans any git source.
func (e *Engine) ScanGit(ctx context.Context, c sources.GitConfig) error {
	logOptions := &gogit.LogOptions{}
	opts := []git.ScanOption{
		git.ScanOptionFilter(c.Filter),
		git.ScanOptionLogOptions(logOptions),
	}

	if c.MaxDepth != 0 {
		opts = append(opts, git.ScanOptionMaxDepth(int64(c.MaxDepth)))
	}
	if c.BaseRef != "" {
		opts = append(opts, git.ScanOptionBaseHash(c.BaseRef))
	}
	if c.HeadRef != "" {
		opts = append(opts, git.ScanOptionHeadCommit(c.HeadRef))
	}
	if c.ExcludeGlobs != nil {
		opts = append(opts, git.ScanOptionExcludeGlobs(c.ExcludeGlobs))
	}
	if c.Bare {
		opts = append(opts, git.ScanOptionBare(c.Bare))
	}
	scanOptions := git.NewScanOptions(opts...)

	connection := &sourcespb.Git{
		// Using Directories here allows us to not pass any
		// authentication. Also by this point, the c.RepoPath should
		// still have been prepared and downloaded to a temporary
		// directory if it was a URL.
		Directories: []string{c.RepoPath},
	}
	var conn anypb.Any
	if err := anypb.MarshalFrom(&conn, connection, proto.MarshalOptions{}); err != nil {
		ctx.Logger().Error(err, "failed to marshal git connection")
		return err
	}

	handle, err := e.sourceManager.Enroll(ctx, "trufflehog - git", new(git.Source).Type(),
		func(ctx context.Context, jobID, sourceID int64) (sources.Source, error) {
			gitSource := git.Source{}
			if err := gitSource.Init(ctx, "trufflehog - git", jobID, sourceID, true, &conn, runtime.NumCPU()); err != nil {
				return nil, err
			}
			gitSource.WithScanOptions(scanOptions)
			// Don't try to clean up the provided directory. That's handled by the
			// caller of ScanGit.
			gitSource.WithPreserveTempDirs(true)
			return &gitSource, nil
		})
	if err != nil {
		return err
	}
	_, err = e.sourceManager.ScheduleRun(ctx, handle)
	return err
}
