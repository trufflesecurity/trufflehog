package engine

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/sirupsen/logrus"
	"github.com/trufflesecurity/trufflehog/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/pkg/sources/git"
)

func (e *Engine) ScanGit(ctx context.Context, gitScanURI, gitScanBranch, headRef string) error {
	var path string
	switch {
	case strings.HasPrefix(gitScanURI, "file://"):
		path = strings.TrimPrefix(gitScanURI, "file://")
	case strings.HasPrefix(gitScanURI, "https://"):
		// TODO: clone repo and get path
		return errors.New("TODO: clone repo and get path")
	default:
		logrus.Fatalf("Unsupported Git URI: %s", gitScanURI)
	}

	repo, err := gogit.PlainOpenWithOptions(path, &gogit.PlainOpenOptions{DetectDotGit: true})
	if err != nil {
		return fmt.Errorf("could open repo: %s: %w", path, err)
	}

	scanOptions := &gogit.LogOptions{
		All:   true,
		Order: gogit.LogOrderCommitterTime,
	}

	if gitScanBranch != "" {
		baseHash, err := git.TryAdditionalBaseRefs(repo, gitScanBranch)
		if err != nil {
			return fmt.Errorf("could not parse base revision: %q: %w", gitScanBranch, err)
		}

		headHash, err := repo.ResolveRevision(plumbing.Revision(headRef))
		if err != nil {
			return fmt.Errorf("could not parse revision: %q: %w", headRef, err)
		}

		baseCommit, err := repo.CommitObject(*baseHash)
		if err != nil {
			return fmt.Errorf("could not find commit: %q: %w", headRef, err)
		}

		logrus.WithFields(logrus.Fields{
			"commit": baseCommit.Hash.String(),
		}).Debug("resolved base reference")

		headCommit, err := repo.CommitObject(*headHash)
		if err != nil {
			return fmt.Errorf("could not find commit: %q: %w", headRef, err)
		}

		logrus.WithFields(logrus.Fields{
			"commit": headCommit.Hash.String(),
		}).Debug("resolved head reference")

		mergeBase, err := baseCommit.MergeBase(headCommit)
		if err != nil {
			return fmt.Errorf("could not find common base between the given references: %q: %w", headRef, err)
		}

		if len(mergeBase) == 0 {
			return fmt.Errorf("no common mergeable base between the given references: %q: %w", headRef, err)
		}

		logrus.WithFields(logrus.Fields{
			"commit": mergeBase[0].Hash.String(),
		}).Debug("resolved common merge base between references")

		scanOptions = &gogit.LogOptions{
			From:  *headHash,
			Order: gogit.LogOrderCommitterTime,
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

	go func() {
		err := gitSource.ScanRepo(ctx, repo, scanOptions, &object.Commit{}, e.ChunksChan())
		if err != nil {
			logrus.WithError(err).Fatal("could not scan repo")
		}
		close(e.ChunksChan())
	}()
	return nil
}
