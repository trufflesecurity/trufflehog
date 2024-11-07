package s3

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/aws/aws-sdk-go/service/s3"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

// ProgressTracker maintains scan progress state for S3 bucket scanning,
// enabling resumable scans by tracking which objects have been successfully processed.
// It provides checkpoints that can be used to resume interrupted scans without missing objects.
type ProgressTracker struct {
	enabled bool

	// completedObjects tracks which indices in the current page have been processed.
	sync.Mutex
	completedObjects []bool

	// progress holds the scan's overall progress state and enables persistence.
	progress *sources.Progress // Reference to source's Progress
}

const defaultMaxObjectsPerPage = 1000

// NewProgressTracker creates a new progress tracker for S3 scanning operations.
// The enabled parameter determines if progress tracking is active, and progress
// provides the underlying mechanism for persisting scan state.
func NewProgressTracker(ctx context.Context, enabled bool, progress *sources.Progress) *ProgressTracker {
	if progress == nil {
		ctx.Logger().Info("Nil progress provided. Progress initialized.")
		progress = new(sources.Progress)
	}

	return &ProgressTracker{
		completedObjects: make([]bool, defaultMaxObjectsPerPage),
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
	p.completedObjects = p.completedObjects[:0]
}

// ResumeInfo represents the state needed to resume an interrupted operation.
// It contains the necessary information to continue processing from the last
// successfully processed item.
type ResumeInfo struct {
	CurrentBucket string `json:"current_bucket"` // Current bucket being scanned
	StartAfter    string `json:"start_after"`    // Last processed object key
}

// GetResumePoint retrieves the last saved checkpoint state if one exists.
// It returns nil if progress tracking is disabled or no resume state exists.
// This method decodes the stored resume information and validates it contains
// the minimum required data to enable resumption.
func (p *ProgressTracker) GetResumePoint(ctx context.Context) (ResumeInfo, error) {
	resume := ResumeInfo{}
	if p.progress == nil {
		return resume, errors.New("progress is nil, progress is required for resuming")
	}

	if !p.enabled || p.progress.EncodedResumeInfo == "" {
		return resume, nil
	}

	var resumeInfo ResumeInfo
	if err := json.Unmarshal([]byte(p.progress.EncodedResumeInfo), &resumeInfo); err != nil {
		return resume, fmt.Errorf("failed to decode resume info: %w", err)
	}

	if resumeInfo.CurrentBucket == "" {
		ctx.Logger().V(2).Info("resume info is missing current bucket, resuming from the beginning")
		return resume, nil
	}

	return ResumeInfo{
		CurrentBucket: resumeInfo.CurrentBucket,
		StartAfter:    resumeInfo.StartAfter,
	}, nil
}

// Complete marks the entire scanning operation as finished and clears the resume state.
// This should only be called once all scanning operations are complete.
func (p *ProgressTracker) Complete(_ context.Context, message string) error {
	if !p.enabled {
		return nil
	}

	// Preserve existing progress counters while clearing resume state.
	p.progress.SetProgressComplete(
		int(p.progress.SectionsCompleted),
		int(p.progress.SectionsRemaining),
		message,
		"", // Clear resume info as scanning is complete
	)
	return nil
}

// UpdateObjectProgress records successfully processed objects within the current page
// and maintains fine-grained resumption checkpoints. It uses a conservative tracking
// strategy that ensures no objects are missed by only checkpointing consecutively
// completed objects.
//
// This method manages the detailed object-level progress tracking and creates
// checkpoints that enable resumption of interrupted scans.
//
// This approach ensures scan reliability by only checkpointing consecutively completed
// objects. While this may result in re-scanning some objects when resuming, it guarantees
// no objects are missed in case of interruption. The linear search through page contents
// is efficient given the fixed maximum page size of 1000 objects.
func (p *ProgressTracker) UpdateObjectProgress(
	ctx context.Context,
	completedIdx int,
	bucket string,
	pageContents []*s3.Object,
) error {
	if !p.enabled {
		return nil
	}

	ctx = context.WithValues(
		ctx,
		"bucket", bucket,
		"completedIdx", completedIdx,
	)
	ctx.Logger().V(5).Info("Updating progress")

	if completedIdx >= len(p.completedObjects) {
		return fmt.Errorf("completed index %d exceeds maximum page size", completedIdx)
	}

	p.Lock()
	defer p.Unlock()

	p.completedObjects[completedIdx] = true

	// Find the highest consecutive completed index.
	lastConsecutiveIdx := -1
	for i := 0; i <= completedIdx; i++ {
		if !p.completedObjects[i] {
			break
		}
		lastConsecutiveIdx = i
	}

	// Update progress if we have at least one completed object.
	if lastConsecutiveIdx < 0 {
		return nil
	}

	obj := pageContents[lastConsecutiveIdx]
	info := &ResumeInfo{CurrentBucket: bucket, StartAfter: *obj.Key}
	encoded, err := json.Marshal(info)
	if err != nil {
		return err
	}

	// Update progress with the number of objects processed in this page
	// and the total objects we know about so far.
	completedCount := int32(lastConsecutiveIdx + 1)
	remainingCount := int32(len(pageContents))

	p.progress.SetProgressComplete(
		int(p.progress.SectionsCompleted+completedCount),
		int(p.progress.SectionsRemaining+remainingCount),
		fmt.Sprintf("Processing: %s/%s", bucket, *obj.Key),
		string(encoded),
	)
	return nil
}
