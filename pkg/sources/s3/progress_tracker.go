package s3

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/aws/aws-sdk-go/service/s3"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

// ProgressTracker maintains scan progress state for S3 bucket scanning,
// enabling resumable scans by tracking which objects have been successfully processed.
// It ensures scan reliability by maintaining checkpoints that can be used to resume
// interrupted scans without missing objects.
type ProgressTracker struct {
	enabled bool

	// completedObjects tracks which indices in the current page have been processed.
	sync.Mutex
	completedObjects map[int]bool

	// progress holds the scan's overall progress state and enables persistence.
	progress *sources.Progress // Reference to source's Progress
}

// NewProgressTracker creates a new progress tracker for S3 scanning operations.
// The enabled parameter determines if progress tracking is active, and progress
// provides the underlying mechanism for persisting scan state.
func NewProgressTracker(enabled bool, progress *sources.Progress) *ProgressTracker {
	return &ProgressTracker{
		completedObjects: make(map[int]bool),
		enabled:          enabled,
		progress:         progress,
	}
}

// Reset prepares the tracker for a new page of objects by clearing the completion state.
func (p *ProgressTracker) Reset(_ context.Context) {
	if !p.enabled {
		return
	}

	p.Lock()
	defer p.Unlock()
	for k := range p.completedObjects {
		delete(p.completedObjects, k)
	}
}

// UpdateProgress records a successfully processed object and updates the scan's resume point.
// It maintains a conservative checkpoint strategy by tracking consecutive completions,
// ensuring no objects are missed when resuming an interrupted scan at the cost of
// potentially re-scanning some objects.
func (p *ProgressTracker) UpdateProgress(
	ctx context.Context,
	completedIdx int,
	bucket string,
	pageContents []*s3.Object,
	pageNumber int,
) error {
	if !p.enabled {
		return nil
	}

	ctx = context.WithValues(
		ctx,
		"bucket", bucket,
		"pageNumber", pageNumber,
		"completedIdx", completedIdx,
	)
	ctx.Logger().V(5).Info("Updating progress")

	p.Lock()
	defer p.Unlock()

	p.completedObjects[completedIdx] = true

	// updateResumePoint maintains a checkpoint of successfully scanned objects
	// to enable scan resumption. It tracks the last consecutively completed object
	// in the page (up to 1000 objects) as a checkpoint. When scanning resumes,
	// it will start from this checkpoint, which may result in re-scanning some
	// objects to ensure no objects are missed.
	// This conservative approach prioritizes completeness over efficiency.
	//
	// The function uses a linear search through page.Contents (max 1000 objects) to find
	// the latest consecutive completed object. While more efficient implementations are
	// possible, the current approach is performant enough given the small fixed size
	// of page.Contents.
	for i := 0; i <= completedIdx; i++ {
		if p.completedObjects[i] {
			continue
		}

		// Found a gap - use previous index if it exists.
		if i > 0 {
			obj := pageContents[i-1]
			info := &ResumeInfo{CurrentBucket: bucket, StartAfter: *obj.Key}
			encoded, err := json.Marshal(info)
			if err != nil {
				return err
			}

			p.progress.SetProgressComplete(
				pageNumber-1,
				len(pageContents),
				fmt.Sprintf("Processing: %s/%s", bucket, *obj.Key),
				string(encoded),
			)
		}
		return nil
	}

	// If we get here, all objects up to completedIdx are done.
	obj := pageContents[completedIdx]
	info := &ResumeInfo{CurrentBucket: bucket, StartAfter: *obj.Key}
	encoded, err := json.Marshal(info)
	if err != nil {
		return err
	}

	p.progress.SetProgressComplete(
		pageNumber-1,
		len(pageContents),
		fmt.Sprintf("Processing: %s/%s", bucket, *obj.Key),
		string(encoded),
	)
	return nil
}
