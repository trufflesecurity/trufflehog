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
// It provides checkpoints that can be used to resume interrupted scans without missing objects.
//
// S3 buckets are organized as flat namespaces of objects identified by unique keys.
// from a specific object key.
//
// The tracker maintains state for the current page of objects (up to 1000) using a boolean array
// to track completion status and an ordered list to record the sequence of completions.
// This enables finding the highest consecutive completed index as a "low water mark".
//
// The key of the object at this index is encoded with the current bucket into a ResumeInfo checkpoint
// and persisted in the Progress.EncodedResumeInfo field as JSON. If a scan is interrupted, it can
// resume from the last checkpoint by using that key as StartAfter.
//
// The low water mark approach ensures scan reliability by only checkpointing consecutively completed
// objects. For example, if objects 0-5 and 7-8 are complete but 6 is incomplete, only objects 0-5
// will be checkpointed. While this may result in re-scanning objects 7-8 when resuming, it guarantees
// no objects are missed in case of interruption.
//
// When scanning multiple buckets, the current bucket is tracked in the checkpoint to enable
// resuming from the correct bucket. The scan will continue from the last checkpointed object
// in that bucket.
//
// For example, if scanning is interrupted after processing 1500 objects across 2 pages:
// Page 1 (objects 0-999): Fully processed, checkpoint saved at object 999
// Page 2 (objects 1000-1999): Partially processed through 1600, but only consecutive through 1499
// On resume: StartAfter=object1499 in saved bucket, scanning continues from object 1500
type ProgressTracker struct {
	enabled bool

	sync.Mutex
	completedObjects []bool
	completionOrder  []int // Track the order in which objects complete

	// progress holds the scan's overall progress state and enables persistence.
	// The EncodedResumeInfo field stores the JSON-encoded ResumeInfo checkpoint.
	progress *sources.Progress // Reference to source's Progress
}

const defaultMaxObjectsPerPage = 1000

// NewProgressTracker creates a new progress tracker for S3 scanning operations.
// The enabled parameter determines if progress tracking is active, and progress
// provides the underlying mechanism for persisting scan state.
func NewProgressTracker(ctx context.Context, enabled bool, progress *sources.Progress) *ProgressTracker {
	ctx.Logger().Info("Creating progress tracker")

	return &ProgressTracker{
		// We are resuming if we have completed objects from a previous scan.
		completedObjects: make([]bool, defaultMaxObjectsPerPage),
		completionOrder:  make([]int, 0, defaultMaxObjectsPerPage),
		enabled:          enabled,
		progress:         progress,
	}
}

// Reset prepares the tracker for a new page of objects by clearing the completion state.
func (p *ProgressTracker) Reset() {
	if !p.enabled {
		return
	}

	p.Lock()
	defer p.Unlock()
	// Store the current completed count before moving to next page.
	p.completedObjects = make([]bool, defaultMaxObjectsPerPage)
	p.completionOrder = make([]int, 0, defaultMaxObjectsPerPage)
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

	return ResumeInfo{CurrentBucket: resumeInfo.CurrentBucket, StartAfter: resumeInfo.StartAfter}, nil
}

// Complete marks the entire scanning operation as finished and clears the resume state.
// This should only be called once all scanning operations are complete.
func (p *ProgressTracker) Complete(_ context.Context, message string) error {
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
// no objects are missed in case of interruption.
//
// For example, consider scanning a page of 10 objects where objects 0-5 and 7-8 complete
// successfully but object 6 fails:
//   - Objects completed: [0,1,2,3,4,5,7,8]
//   - The checkpoint will only include objects 0-5 since they are consecutive
//   - If scanning is interrupted and resumed:
//     - Scan resumes after object 5 (the last checkpoint)
//     - Objects 7-8 will be re-scanned even though they completed before
//     - This ensures object 6 is not missed
func (p *ProgressTracker) UpdateObjectProgress(
	ctx context.Context,
	completedIdx int,
	bucket string,
	pageContents []*s3.Object,
) error {
	if !p.enabled {
		return nil
	}

	ctx = context.WithValues(ctx, "bucket", bucket, "completedIdx", completedIdx)
	ctx.Logger().V(5).Info("Updating progress")

	if completedIdx >= len(p.completedObjects) {
		return fmt.Errorf("completed index %d exceeds maximum page size", completedIdx)
	}

	p.Lock()
	defer p.Unlock()

	// Only track completion if this is the first time this index is marked complete.
	if !p.completedObjects[completedIdx] {
		p.completedObjects[completedIdx] = true
		p.completionOrder = append(p.completionOrder, completedIdx)
	}

	// Find the highest safe checkpoint we can create.
	lastSafeIdx := -1
	var safeIndices [defaultMaxObjectsPerPage]bool

	// Mark all completed indices.
	for _, idx := range p.completionOrder {
		safeIndices[idx] = true
	}

	// Find the highest consecutive completed index.
	for i := range len(p.completedObjects) {
		if !safeIndices[i] {
			break
		}
		lastSafeIdx = i
	}

	// Update progress if we have at least one completed object.
	if lastSafeIdx < 0 {
		return nil
	}

	obj := pageContents[lastSafeIdx]
	info := &ResumeInfo{CurrentBucket: bucket, StartAfter: *obj.Key}
	encoded, err := json.Marshal(info)
	if err != nil {
		return err
	}

	// Purposefully avoid updating any progress counts.
	// Only update resume info.
	p.progress.SetProgressComplete(
		int(p.progress.SectionsCompleted),
		int(p.progress.SectionsRemaining),
		p.progress.Message,
		string(encoded),
	)
	return nil
}
