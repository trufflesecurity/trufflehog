// Code used exclusively by the enterprise version.
// https://github.com/trufflesecurity/trufflehog/pull/3298#issuecomment-2510010947

package github

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"

	"github.com/google/go-github/v67/github"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/handlers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

// Chunks emits chunks of bytes over a channel.
func (s *Source) Chunks(ctx context.Context, chunksChan chan *sources.Chunk, targets ...sources.ChunkingTarget) error {
	chunksReporter := sources.ChanReporter{Ch: chunksChan}
	// If targets are provided, we're only scanning the data in those targets.
	// Otherwise, we're scanning all data.
	// This allows us to only scan the commit where a vulnerability was found.
	if len(targets) > 0 {
		errs := s.scanTargets(ctx, targets, chunksReporter)
		return errors.Join(errs...)
	}

	// Reset consumption and rate limit metrics on each run.
	githubNumRateLimitEncountered.WithLabelValues(s.name).Set(0)
	githubSecondsSpentRateLimited.WithLabelValues(s.name).Set(0)
	githubReposScanned.WithLabelValues(s.name).Set(0)

	// We don't care about handling enumerated values as they happen during
	// the normal Chunks flow because we enumerate and scan in two steps.
	noopReporter := sources.VisitorReporter{
		VisitUnit: func(context.Context, sources.SourceUnit) error {
			return nil
		},
	}
	err := s.Enumerate(ctx, noopReporter)
	if err != nil {
		return fmt.Errorf("error enumerating: %w", err)
	}

	return s.scan(ctx, chunksReporter)
}

func (s *Source) scan(ctx context.Context, reporter sources.ChunkReporter) error {
	var scannedCount uint64 = 1

	ctx.Logger().V(2).Info("Found repos to scan", "count", len(s.repos))

	// If there is resume information available, limit this scan to only the repos that still need scanning.
	reposToScan, progressIndexOffset := sources.FilterReposToResume(s.repos, s.GetProgress().EncodedResumeInfo)
	s.repos = reposToScan

	for i, repoURL := range s.repos {
		s.jobPool.Go(func() error {
			if common.IsDone(ctx) {
				return nil
			}
			ctx := context.WithValue(ctx, "repo", repoURL)

			// TODO: set progress complete is being called concurrently with i
			s.setProgressCompleteWithRepo(i, progressIndexOffset, repoURL)
			// Ensure the repo is removed from the resume info after being scanned.
			defer func(s *Source, repoURL string) {
				s.resumeInfoMutex.Lock()
				defer s.resumeInfoMutex.Unlock()
				s.resumeInfoSlice = sources.RemoveRepoFromResumeInfo(s.resumeInfoSlice, repoURL)
			}(s, repoURL)

			if err := s.scanRepo(ctx, repoURL, reporter); err != nil {
				ctx.Logger().Error(err, "error scanning repo")
				return nil
			}

			atomic.AddUint64(&scannedCount, 1)
			return nil
		})
	}

	_ = s.jobPool.Wait()
	s.SetProgressComplete(len(s.repos), len(s.repos), "Completed GitHub scan", "")

	return nil
}

func (s *Source) scanTargets(ctx context.Context, targets []sources.ChunkingTarget, reporter sources.ChunkReporter) []error {
	var errs []error
	for _, tgt := range targets {
		if err := s.scanTarget(ctx, tgt, reporter); err != nil {
			ctx.Logger().Error(err, "error scanning target")
			errs = append(errs, &sources.TargetedScanError{Err: err, SecretID: tgt.SecretID})
		}
	}

	return errs
}

func (s *Source) scanTarget(ctx context.Context, target sources.ChunkingTarget, reporter sources.ChunkReporter) error {
	metaType, ok := target.QueryCriteria.GetData().(*source_metadatapb.MetaData_Github)
	if !ok {
		return fmt.Errorf("unable to cast metadata type for targeted scan")
	}
	meta := metaType.Github

	u, err := url.Parse(meta.GetLink())
	if err != nil {
		return fmt.Errorf("unable to parse GitHub URL: %w", err)
	}

	// The owner is the second segment and the repo is the third segment of the path.
	// Ex: https://github.com/owner/repo/.....
	segments := strings.Split(u.Path, "/")
	if len(segments) < 3 {
		return fmt.Errorf("invalid GitHub URL")
	}

	readCloser, resp, err := s.connector.APIClient().Repositories.DownloadContents(
		ctx,
		segments[1],
		segments[2],
		meta.GetFile(),
		&github.RepositoryContentGetOptions{Ref: meta.GetCommit()})
	// As of this writing, if the returned readCloser is not nil, it's just the Body of the returned github.Response, so
	// there's no need to independently close it.
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		return fmt.Errorf("could not download file for scan: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected HTTP response status when trying to download file for scan: %v", resp.Status)
	}

	chunkSkel := sources.Chunk{
		SourceType: s.Type(),
		SourceName: s.name,
		SourceID:   s.SourceID(),
		JobID:      s.JobID(),
		SecretID:   target.SecretID,
		SourceMetadata: &source_metadatapb.MetaData{
			Data: &source_metadatapb.MetaData_Github{Github: meta},
		},
		Verify: s.verify,
	}
	fileCtx := context.WithValues(ctx, "path", meta.GetFile())
	return handlers.HandleFile(fileCtx, readCloser, &chunkSkel, reporter)
}
