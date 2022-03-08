package engine

import (
	"context"
	"fmt"
	"runtime"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/sirupsen/logrus"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/git"
)

func (e *Engine) ScanGit(ctx context.Context, repoPath, headRef, baseRef string, maxDepth int, filter *common.Filter) error {
	repo, err := gogit.PlainOpenWithOptions(repoPath, &gogit.PlainOpenOptions{DetectDotGit: true})
	if err != nil {
		return fmt.Errorf("could open repo: %s: %w", repoPath, err)
	}

	logOptions := &gogit.LogOptions{
		All: true,
	}

	var sinceCommit, headCommit *object.Commit
	if len(baseRef) > 0 {
		baseHash := plumbing.NewHash(baseRef)
		if baseHash.IsZero() {
			base, err := git.TryAdditionalBaseRefs(repo, baseRef)
			if err == nil && !base.IsZero() {
				baseHash = *base
			}
		}
		sinceCommit, err = repo.CommitObject(baseHash)
		if err != nil {
			return fmt.Errorf("unable to resolve commit %s: %s", baseRef, err)
		}
	}

	if headRef == "" {
		head, err := repo.Head()
		if err != nil {
			return err
		}
		headRef = head.Hash().String()
	}
	headHash, err := git.TryAdditionalBaseRefs(repo, headRef)
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

	gitSource := git.NewGit(sourcespb.SourceType_SOURCE_TYPE_GIT, 0, 0, "local", true, runtime.NumCPU(),
		func(file, email, commit, timestamp, repository string) *source_metadatapb.MetaData {
			return &source_metadatapb.MetaData{
				Data: &source_metadatapb.MetaData_Git{
					Git: &source_metadatapb.Git{
						Commit:     commit,
						File:       file,
						Email:      email,
						Repository: repository,
						Timestamp:  timestamp,
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
		opts = append(opts, git.ScanOptionBaseCommit(sinceCommit))
	}
	if headCommit != nil {
		opts = append(opts, git.ScanOptionHeadCommit(headCommit))
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
