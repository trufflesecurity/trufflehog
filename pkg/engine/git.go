package engine

import (
	"context"
	"fmt"
	"runtime"

	"github.com/go-git/go-git/v5/plumbing/object"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/sirupsen/logrus"

	"github.com/trufflesecurity/trufflehog/pkg/common"
	"github.com/trufflesecurity/trufflehog/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/pkg/sources/git"
)

func (e *Engine) ScanGit(ctx context.Context, repoPath, gitScanBranch, headRef string, sinceHash *plumbing.Hash, maxDepth int, filter *common.Filter) error {
	repo, err := gogit.PlainOpenWithOptions(repoPath, &gogit.PlainOpenOptions{DetectDotGit: true})
	if err != nil {
		return fmt.Errorf("could open repo: %s: %w", repoPath, err)
	}

	logOptions := &gogit.LogOptions{
		All: true,
	}

	var sinceCommit, headCommit *object.Commit
	if !sinceHash.IsZero() {
		sinceCommit, err = repo.CommitObject(*sinceHash)
		if err != nil {
			return fmt.Errorf("unable to resolve commit %s: %s", sinceHash.String(), err)
		}
	}

	if gitScanBranch != "" {
		headHash, err := git.TryAdditionalBaseRefs(repo, gitScanBranch)
		if err != nil {
			return fmt.Errorf("could not parse revision: %q: %w", headRef, err)
		}

		headCommit, err = repo.CommitObject(*headHash)
		if err != nil {
			return fmt.Errorf("could not find commit: %q: %w", headRef, err)
		}

		logrus.WithFields(logrus.Fields{
			"commit": headCommit.Hash.String(),
		}).Debug("resolved head reference")

		logOptions.From = headCommit.Hash
		logOptions.All = false
	}

	if sinceCommit != nil && headCommit != nil {
		if ok, _ := sinceCommit.IsAncestor(headCommit); !ok {
			return fmt.Errorf("unable to scan from requested head to end commit. %s is not an ancestor of %s", sinceCommit.Hash.String(), headCommit.Hash.String())
		}
	}

	gitSource := git.NewGit(sourcespb.SourceType_SOURCE_TYPE_GIT, 0, 0, "local", true, runtime.NumCPU(),
		func(file, email, commit, repository string) *source_metadatapb.MetaData {
			return &source_metadatapb.MetaData{
				Data: &source_metadatapb.MetaData_Git{
					Git: &source_metadatapb.Git{
						Commit:     commit,
						File:       file,
						Email:      email,
						Repository: repository,
					},
				},
			}
		})

	opts := []git.ScanOption{
		git.ScanOptionFilter(filter),
		git.ScanOptionLogOptions(logOptions),
	}
	// TODO: Add kingpin type that can differentiate between `not set` and `0` for int.
	if maxDepth != 0 {
		opts = append(opts, git.ScanOptionMaxDepth(int64(maxDepth)))
	}
	if sinceCommit != nil {
		opts = append(opts, git.ScanOptionSinceCommit(sinceCommit))
	}
	scanOptions := git.NewScanOptions(opts...)

	go func() {
		err := gitSource.ScanRepo(ctx, repo, scanOptions, e.ChunksChan())
		if err != nil {
			logrus.WithError(err).Fatal("could not scan repo")
		}
		close(e.ChunksChan())
	}()
	return nil
}
