package huggingface

import (
	"fmt"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/handlers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sanitizer"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

// maxBucketFileSize is the largest bucket file that will be downloaded and
// scanned. Files larger than this are skipped.
const maxBucketFileSize = 250 * 1024 * 1024 // 250MB

// cacheBucketInfo fetches bucket metadata (notably its visibility) and caches
// it, then adds the bucket to the list of buckets to scan. Unlike models,
// spaces, and datasets, buckets are not git repos, so they are keyed by their
// plain "namespace/name" ID instead of a clone URL.
func (s *Source) cacheBucketInfo(ctx context.Context, bucketID string) error {
	bucketCtx := context.WithValue(ctx, BUCKET, bucketID)

	if _, ok := s.repoInfoCache.get(bucketID); !ok {
		bucketCtx.Logger().V(2).Info("Caching bucket info")
		bucket, err := s.apiClient.GetBucket(bucketCtx, bucketID)
		if err != nil {
			bucketCtx.Logger().Error(err, "failed to fetch bucket")
			return err
		}
		if bucket.BucketID == "" {
			bucketCtx.Logger().Error(fmt.Errorf("no bucket found for bucket"), bucketID)
			return nil
		}
		s.repoInfoCache.put(bucketID, repoInfo{
			owner:        strings.Split(bucket.BucketID, "/")[0],
			name:         strings.Split(bucket.BucketID, "/")[1],
			fullName:     bucket.BucketID,
			visibility:   getVisibility(bucket.IsPrivate),
			resourceType: BUCKET,
		})
	}
	s.buckets = append(s.buckets, bucketID)
	return nil
}

// fetchAndCacheBuckets enumerates all buckets belonging to an author (user or
// org) and caches the ones that survive include/exclude filtering.
func (s *Source) fetchAndCacheBuckets(ctx context.Context, author string) error {
	buckets, err := s.apiClient.ListBucketsByAuthor(ctx, author)
	if err != nil {
		return err
	}
	for _, bucket := range buckets {
		s.filteredBucketsCache.Set(bucket.BucketID, bucket.BucketID)
		// Set is a no-op for buckets excluded by include/ignore globs.
		if _, ok := s.filteredBucketsCache.Get(bucket.BucketID); !ok {
			continue
		}
		if err := s.cacheBucketInfo(ctx, bucket.BucketID); err != nil {
			continue
		}
	}
	return nil
}

// scanBuckets lists and scans the files of all enumerated buckets. Buckets
// are object storage rather than git repos, so files are downloaded
// individually and chunked directly.
func (s *Source) scanBuckets(ctx context.Context, chunksChan chan *sources.Chunk) error {
	ctx.Logger().V(2).Info("Found buckets to scan", "count", len(s.buckets))

	scanErrs := sources.NewScanErrors()
	reporter := sources.ChanReporter{Ch: chunksChan}

	for _, bucketID := range s.buckets {
		bucketInfo, ok := s.repoInfoCache.get(bucketID)
		if !ok {
			// This should never happen.
			err := fmt.Errorf("no bucketInfo for bucket: %s", bucketID)
			ctx.Logger().Error(err, "failed to scan bucket")
			continue
		}
		bucketCtx := context.WithValues(ctx, BUCKET, bucketID)

		files, err := s.apiClient.ListBucketFiles(bucketCtx, bucketID)
		if err != nil {
			scanErrs.Add(fmt.Errorf("error listing files in bucket %s: %w", bucketID, err))
			continue
		}

		for _, file := range files {
			s.jobPool.Go(func() error {
				if common.IsDone(bucketCtx) {
					return nil
				}
				if file.Type != "file" {
					return nil
				}
				if file.Size > maxBucketFileSize {
					bucketCtx.Logger().V(2).Info("Skipping bucket file: exceeds max size", "path", file.Path, "size", file.Size)
					return nil
				}
				if err := s.scanBucketFile(bucketCtx, bucketID, bucketInfo, file, reporter); err != nil {
					scanErrs.Add(fmt.Errorf("error scanning file %s in bucket %s: %w", file.Path, bucketID, err))
				}
				return nil
			})
		}
	}

	_ = s.jobPool.Wait()
	if scanErrs.Count() > 0 {
		ctx.Logger().V(0).Info("failed to scan some buckets", "error_count", scanErrs.Count(), "errors", scanErrs.String())
	}
	s.SetProgressComplete(len(s.buckets), len(s.buckets), "Completed HuggingFace bucket scan", "")
	return nil
}

// scanBucketFile downloads a single bucket file and chunks its content.
func (s *Source) scanBucketFile(ctx context.Context, bucketID string, bucketInfo repoInfo, file BucketFile, reporter sources.ChanReporter) error {
	body, err := s.apiClient.DownloadBucketFile(ctx, bucketID, file.Path)
	if err != nil {
		return err
	}
	defer func() { _ = body.Close() }()

	chunkSkel := &sources.Chunk{
		SourceType: s.Type(),
		SourceName: s.name,
		SourceID:   s.SourceID(),
		JobID:      s.JobID(),
		SourceMetadata: &source_metadatapb.MetaData{
			Data: &source_metadatapb.MetaData_Huggingface{
				Huggingface: &source_metadatapb.Huggingface{
					File:         sanitizer.UTF8(file.Path),
					Link:         sanitizer.UTF8(fmt.Sprintf("%s/%s/%s/resolve/%s", s.conn.Endpoint, BucketsRoute, bucketID, escapePathSegments(file.Path))),
					Repository:   sanitizer.UTF8(fmt.Sprintf("%s/%s/%s", s.conn.Endpoint, BucketsRoute, bucketID)),
					Visibility:   bucketInfo.visibility,
					ResourceType: BUCKET,
				},
			},
		},
		SourceVerify: s.verify,
	}

	return handlers.HandleFile(ctx, body, chunkSkel, reporter)
}
