package s3

import (
	"encoding/json"
	"fmt"
	"sync"

	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

// TODO [INS-207] Add role to legacy scan resumption info

// Checkpointer maintains resumption state for S3 bucket scanning,
// enabling resumable scans by tracking which objects have been successfully processed.
// It provides checkpoints that can be used to resume interrupted scans without missing objects.
//
// S3 buckets are organized as flat namespaces of objects identified by unique keys.
// The checkpointer maintains state for the current page of objects (up to 1000) using a boolean array
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
// Unit scans are also supported. The encoded resume info in this case tracks the last processed object
// for each unit separately by using the SetEncodedResumeInfoFor method on Progress. To use the
// checkpointer for unit scans, call SetIsUnitScan(true) before starting the scan.
//
// For example, if scanning is interrupted after processing 1500 objects across 2 pages:
// Page 1 (objects 0-999): Fully processed, checkpoint saved at object 999
// Page 2 (objects 1000-1999): Partially processed through 1600, but only consecutive through 1499
// On resume: StartAfter=object1499 in saved bucket, scanning continues from object 1500
//
// Important constraints:
// - Only tracks completion state for a single page of objects (up to 1000)
// - Supports concurrent object processing within a page
// - Does NOT support concurrent page processing
// - Must be Reset() between pages
type Checkpointer struct {
	// completedObjects tracks which indices in the current page have been processed.
	mu               sync.Mutex // protects concurrent access to completion state.
	completedObjects []bool
	completionOrder  []int // Track the order in which objects complete

	// lowestIncompleteIdx tracks the first index that hasn't been completed.
	// This optimizes checkpoint creation by avoiding recalculation.
	lowestIncompleteIdx int

	// progress holds the scan's overall progress state and enables persistence.
	// The EncodedResumeInfo field stores the JSON-encoded ResumeInfo checkpoint.
	progress *sources.Progress // Reference to source's Progress

	isUnitScan bool // Indicates if scanning is done in unit scan mode
}

const defaultMaxObjectsPerPage = 1000

// NewCheckpointer creates a new checkpointer for S3 scanning operations.
// The progress provides the underlying mechanism for persisting scan state.
func NewCheckpointer(ctx context.Context, progress *sources.Progress, isUnitScan bool) *Checkpointer {
	ctx.Logger().Info("Creating checkpointer")

	return &Checkpointer{
		// We are resuming if we have completed objects from a previous scan.
		completedObjects: make([]bool, defaultMaxObjectsPerPage),
		completionOrder:  make([]int, 0, defaultMaxObjectsPerPage),
		progress:         progress,
		isUnitScan:       isUnitScan,
	}
}

// Reset prepares the tracker for a new page of objects by clearing the completion state.
// Must be called before processing each new page of objects.
func (p *Checkpointer) Reset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	// Store the current completed count before moving to next page.
	p.completedObjects = make([]bool, defaultMaxObjectsPerPage)
	p.completionOrder = make([]int, 0, defaultMaxObjectsPerPage)
	p.lowestIncompleteIdx = 0
}

// ResumeInfo represents the state needed to resume an interrupted operation.
// It contains the necessary information to continue processing from the last
// successfully processed item.
type ResumeInfo struct {
	CurrentBucket string `json:"current_bucket"` // Current bucket being scanned
	StartAfter    string `json:"start_after"`    // Last processed object key
	Role          string `json:"role"`           // Role used for scanning
}

// ResumePoint retrieves the last saved checkpoint state if one exists.
// It returns nil if no resume state exists.
// This method decodes the stored resume information and validates it contains
// the minimum required data to enable resumption.
func (p *Checkpointer) ResumePoint(ctx context.Context) (ResumeInfo, error) {
	resume := ResumeInfo{}

	if p.progress.EncodedResumeInfo == "" {
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

	return ResumeInfo{CurrentBucket: resumeInfo.CurrentBucket, StartAfter: resumeInfo.StartAfter, Role: resumeInfo.Role}, nil
}

// Complete marks the entire scanning operation as finished and clears the resume state.
// This should only be called once all scanning operations are complete.
func (p *Checkpointer) Complete(_ context.Context, message string) error {
	// Preserve existing progress counters while clearing resume state.
	p.progress.SetProgressComplete(
		int(p.progress.SectionsCompleted),
		int(p.progress.SectionsRemaining),
		message,
		"", // Clear resume info as scanning is complete
	)
	return nil
}

// UpdateObjectCompletion records successfully processed objects within the current page
// and maintains fine-grained resumption checkpoints. It uses a conservative tracking
// strategy that ensures no objects are missed by only checkpointing consecutively
// completed objects.
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
//     -- Scan resumes after object 5 (the last checkpoint)
//     -- Objects 7-8 will be re-scanned even though they completed before
//     -- This ensures object 6 is not missed
//
// Thread-safe for concurrent object processing within a single page.
// WARNING: Not safe for concurrent page processing.
func (p *Checkpointer) UpdateObjectCompletion(
	ctx context.Context,
	completedIdx int,
	bucket string,
	role string,
	pageContents []s3types.Object,
) error {
	ctx = context.WithValues(ctx, "bucket", bucket, "role", role, "completedIdx", completedIdx)
	ctx.Logger().V(5).Info("Updating progress")

	if completedIdx >= len(p.completedObjects) {
		return fmt.Errorf("completed index %d exceeds maximum page size", completedIdx)
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// Only process if this is the first time this index is marked complete.
	if !p.completedObjects[completedIdx] {
		p.completedObjects[completedIdx] = true
		p.completionOrder = append(p.completionOrder, completedIdx)

		// If we completed the lowest incomplete index, scan forward to find the new lowest.
		if completedIdx == p.lowestIncompleteIdx {
			p.advanceLowestIncompleteIdx()
		}
	}

	// lowestIncompleteIdx points to first incomplete object, so everything before
	// it is complete. We want to checkpoint at the last complete object.
	checkpointIdx := p.lowestIncompleteIdx - 1
	if checkpointIdx < 0 {
		return nil // No completed objects yet
	}
	if checkpointIdx >= len(pageContents) {
		// this should never happen
		return fmt.Errorf("checkpoint index %d exceeds page contents size %d", checkpointIdx, len(pageContents))
	}
	obj := pageContents[checkpointIdx]

	return p.updateCheckpoint(bucket, role, *obj.Key)
}

// advanceLowestIncompleteIdx moves the lowest incomplete index forward to the next incomplete object.
// Must be called with lock held.
func (p *Checkpointer) advanceLowestIncompleteIdx() {
	for p.lowestIncompleteIdx < len(p.completedObjects) &&
		p.completedObjects[p.lowestIncompleteIdx] {
		p.lowestIncompleteIdx++
	}
}

// updateCheckpoint persists the current resumption state.
// Must be called with lock held.
func (p *Checkpointer) updateCheckpoint(bucket string, role string, lastKey string) error {
	if p.isUnitScan {
		unitID := constructS3SourceUnitID(bucket, role)
		// track sub-unit resumption state
		p.progress.SetEncodedResumeInfoFor(unitID, lastKey)
		return nil
	}

	encoded, err := json.Marshal(&ResumeInfo{CurrentBucket: bucket, StartAfter: lastKey, Role: role})
	if err != nil {
		return fmt.Errorf("failed to encode resume info: %w", err)
	}

	p.progress.SetProgressComplete(
		int(p.progress.SectionsCompleted),
		int(p.progress.SectionsRemaining),
		p.progress.Message,
		string(encoded),
	)
	return nil
}
