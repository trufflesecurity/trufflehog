package s3

import (
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/stretchr/testify/assert"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

func TestProgressTrackerReset(t *testing.T) {
	tests := []struct {
		name     string
		enabled  bool
		capacity int
	}{
		{
			name:     "reset with enabled tracker",
			enabled:  true,
			capacity: 10,
		},
		{
			name:     "reset with disabled tracker",
			enabled:  false,
			capacity: 5,
		},
		{
			name:     "reset with zero capacity",
			enabled:  true,
			capacity: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			progress := new(sources.Progress)
			tracker := NewProgressTracker(tt.enabled, progress)

			tracker.completedObjects[1] = true
			tracker.completedObjects[2] = true

			tracker.Reset(ctx)

			if !tt.enabled {
				assert.Equal(t, 2, len(tracker.completedObjects), "Reset did not clear completed objects")
				return
			}

			assert.Equal(t, 0, len(tracker.completedObjects), "Reset did not clear completed objects")
		})
	}
}

func setupTestTracker(t *testing.T, enabled bool, progress *sources.Progress, pageSize int) (*ProgressTracker, *s3.ListObjectsV2Output) {
	t.Helper()

	tracker := NewProgressTracker(enabled, progress)
	page := &s3.ListObjectsV2Output{Contents: make([]*s3.Object, pageSize)}
	for i := range pageSize {
		key := fmt.Sprintf("key-%d", i)
		page.Contents[i] = &s3.Object{Key: &key}
	}
	return tracker, page
}

func TestProgressTrackerUpdateProgressDisabled(t *testing.T) {
	t.Parallel()

	progress := new(sources.Progress)
	tracker, page := setupTestTracker(t, false, progress, 5)

	err := tracker.UpdateProgress(context.Background(), 1, "test-bucket", page.Contents, 1)
	assert.NoError(t, err, "Error updating progress when tracker disabled")

	assert.Empty(t, progress.EncodedResumeInfo, "Progress updated when tracker disabled")
}

func TestProgressTrackerUpdateProgressEnabled(t *testing.T) {
	tests := []struct {
		name         string
		completedIdx int
		pageSize     int
		preCompleted map[int]bool
		pageNumber   int
	}{
		{
			name:         "first object in first page",
			completedIdx: 0,
			pageSize:     3,
			pageNumber:   1,
		},
		{
			name:         "last object in page",
			completedIdx: 2,
			pageSize:     3,
			pageNumber:   1,
		},
		{
			name:         "with gap in completion",
			completedIdx: 2,
			pageSize:     3,
			preCompleted: map[int]bool{0: true, 2: true},
			pageNumber:   1,
		},
		{
			name:         "consecutive completions",
			completedIdx: 2,
			pageSize:     3,
			preCompleted: map[int]bool{0: true, 1: true},
			pageNumber:   2,
		},
		{
			name:         "large page size",
			completedIdx: 999,
			pageSize:     1000,
			pageNumber:   1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			progress := new(sources.Progress)
			tracker, page := setupTestTracker(t, true, progress, tt.pageSize)

			if tt.preCompleted != nil {
				for k, v := range tt.preCompleted {
					tracker.completedObjects[k] = v
				}
			}

			err := tracker.UpdateProgress(ctx, tt.completedIdx, "test-bucket", page.Contents, tt.pageNumber)
			assert.NoError(t, err, "Unexpected error updating progress")
			assert.NotEmpty(t, progress.EncodedResumeInfo, "Expected progress update")
		})
	}
}
