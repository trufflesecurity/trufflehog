package engine

import (
	"context"
	"fmt"
	"runtime"

	"github.com/go-errors/errors"
	"github.com/go-git/go-git/v5/plumbing/object"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/sirupsen/logrus"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/git"
)

func (e *Engine) ScanGit(ctx context.Context, repoPath, headRef, baseRef string, maxDepth int, filter *common.Filter) error {
	logOptions := &gogit.LogOptions{}
	opts := []git.ScanOption{
		git.ScanOptionFilter(filter),
		git.ScanOptionLogOptions(logOptions),
	}

	repo, err := gogit.PlainOpenWithOptions(repoPath, &gogit.PlainOpenOptions{DetectDotGit: true})
	if err != nil {
		return fmt.Errorf("could open repo: %s: %w", repoPath, err)
	}

	var baseCommit *object.Commit
	if len(baseRef) > 0 {
		baseHash := plumbing.NewHash(baseRef)
		if !plumbing.IsHash(baseRef) {
			base, err := git.TryAdditionalBaseRefs(repo, baseRef)
			if err != nil {
				return errors.WrapPrefix(err, "unable to resolve base ref", 0)
			} else {
				baseRef = base.String()
				baseCommit, _ = repo.CommitObject(plumbing.NewHash(baseRef))
			}
		} else {
			baseCommit, err = repo.CommitObject(baseHash)
			if err != nil {
				return errors.WrapPrefix(err, "unable to resolve base ref", 0)
			}
		}
	}

	var headCommit *object.Commit
	if len(headRef) > 0 {
		headHash := plumbing.NewHash(headRef)
		if !plumbing.IsHash(headRef) {
			head, err := git.TryAdditionalBaseRefs(repo, headRef)
			if err != nil {
				return errors.WrapPrefix(err, "unable to resolve head ref", 0)
			} else {
				headRef = head.String()
				headCommit, _ = repo.CommitObject(plumbing.NewHash(baseRef))
			}
		} else {
			headCommit, err = repo.CommitObject(headHash)
			if err != nil {
				return errors.WrapPrefix(err, "unable to resolve head ref", 0)
			}
		}
	}

	// If baseCommit is an ancestor of headCommit, update baseRef to be the common ancestor.
	if headCommit != nil && baseCommit != nil {
		mergeBase, err := headCommit.MergeBase(baseCommit)
		if err != nil || len(mergeBase) < 1 {
			return errors.WrapPrefix(err, "could not find common base between the given references", 0)
		}
		baseRef = mergeBase[0].Hash.String()
	}

	if maxDepth != 0 {
		opts = append(opts, git.ScanOptionMaxDepth(int64(maxDepth)))
	}
	if baseRef != "" {
		opts = append(opts, git.ScanOptionBaseHash(baseRef))
	}
	if headRef != "" {
		opts = append(opts, git.ScanOptionHeadCommit(headRef))
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

	e.sourcesWg.Add(1)
	go func() {
		defer e.sourcesWg.Done()
		err := gitSource.ScanRepo(ctx, repo, repoPath, scanOptions, e.ChunksChan())
		if err != nil {
			logrus.WithError(err).Fatal("could not scan repo")
		}
	}()
	return nil
}
