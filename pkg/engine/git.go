package engine

import (
	"fmt"
	"runtime"

	gogit "github.com/go-git/go-git/v5"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
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

	repo, err := gogit.PlainOpenWithOptions(c.RepoPath, &gogit.PlainOpenOptions{DetectDotGit: true})
	if err != nil {
		return fmt.Errorf("could not open repo: %s: %w", c.RepoPath, err)
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
	scanOptions := git.NewScanOptions(opts...)

	gitSource := git.NewGit(sourcespb.SourceType_SOURCE_TYPE_GIT, 0, 0, "trufflehog - git", true, runtime.NumCPU(),
		func(file, email, commit, timestamp, repository string, line int64) *source_metadatapb.MetaData {
			return &source_metadatapb.MetaData{
				Data: &source_metadatapb.MetaData_Git{
					Git: &source_metadatapb.Git{
						Commit:     commit,
						File:       file,
						Email:      email,
						Repository: repository,
						Timestamp:  timestamp,
						Line:       line,
					},
				},
			}
		})

	ctx = context.WithValues(ctx,
		"source_type", sourcespb.SourceType_SOURCE_TYPE_GIT.String(),
		"source_name", "git",
	)
	e.sourcesWg.Add(1)
	go func() {
		defer common.RecoverWithExit(ctx)
		defer e.sourcesWg.Done()
		err := gitSource.ScanRepo(ctx, repo, c.RepoPath, scanOptions, e.ChunksChan())
		if err != nil {
			ctx.Logger().Error(err, "could not scan repo")
		}
	}()
	return nil
}
