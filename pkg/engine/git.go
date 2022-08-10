package engine

import (
	"context"
	"fmt"
	"runtime"

	"github.com/go-errors/errors"
	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/sirupsen/logrus"

	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/git"
)

// ScanGit scans any git source.
func (e *Engine) ScanGit(ctx context.Context, c *sources.Config) error {
	if c == nil {
		return errors.New("nil config for ScanGit")
	}

	logOptions := &gogit.LogOptions{}
	opts := []git.ScanOption{
		git.ScanOptionFilter(c.Filter),
		git.ScanOptionLogOptions(logOptions),
	}

	repo, err := gogit.PlainOpenWithOptions(c.RepoPath, &gogit.PlainOpenOptions{DetectDotGit: true})
	if err != nil {
		return fmt.Errorf("could open repo: %s: %w", c.RepoPath, err)
	}

	var baseCommit *object.Commit
	if len(c.BaseRef) > 0 {
		baseHash := plumbing.NewHash(c.BaseRef)
		if !plumbing.IsHash(c.BaseRef) {
			base, err := git.TryAdditionalBaseRefs(repo, c.BaseRef)
			if err != nil {
				return errors.WrapPrefix(err, "unable to resolve base ref", 0)
			} else {
				c.BaseRef = base.String()
				baseCommit, _ = repo.CommitObject(plumbing.NewHash(c.BaseRef))
			}
		} else {
			baseCommit, err = repo.CommitObject(baseHash)
			if err != nil {
				return errors.WrapPrefix(err, "unable to resolve base ref", 0)
			}
		}
	}

	var headCommit *object.Commit
	if len(c.HeadRef) > 0 {
		headHash := plumbing.NewHash(c.HeadRef)
		if !plumbing.IsHash(c.HeadRef) {
			head, err := git.TryAdditionalBaseRefs(repo, c.HeadRef)
			if err != nil {
				return errors.WrapPrefix(err, "unable to resolve head ref", 0)
			} else {
				c.HeadRef = head.String()
				headCommit, _ = repo.CommitObject(plumbing.NewHash(c.BaseRef))
			}
		} else {
			headCommit, err = repo.CommitObject(headHash)
			if err != nil {
				return errors.WrapPrefix(err, "unable to resolve head ref", 0)
			}
		}
	}

	// If baseCommit is an ancestor of headCommit, update c.BaseRef to be the common ancestor.
	if headCommit != nil && baseCommit != nil {
		mergeBase, err := headCommit.MergeBase(baseCommit)
		if err != nil || len(mergeBase) < 1 {
			return errors.WrapPrefix(err, "could not find common base between the given references", 0)
		}
		c.BaseRef = mergeBase[0].Hash.String()
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

	e.sourcesWg.Add(1)
	go func() {
		defer e.sourcesWg.Done()
		err := gitSource.ScanRepo(ctx, repo, c.RepoPath, scanOptions, e.ChunksChan())
		if err != nil {
			logrus.WithError(err).Fatal("could not scan repo")
		}
	}()
	return nil
}
