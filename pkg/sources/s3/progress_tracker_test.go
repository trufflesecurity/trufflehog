package s3

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/stretchr/testify/assert"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

func TestProgressTrackerReset(t *testing.T) {
	tests := []struct {
		name    string
		enabled bool
	}{
		{name: "reset with enabled tracker", enabled: true},
		{name: "reset with disabled tracker", enabled: false},
		{name: "reset with zero capacity", enabled: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			progress := new(sources.Progress)
			tracker := NewProgressTracker(ctx, tt.enabled, progress)

			tracker.completedObjects[1] = true
			tracker.completedObjects[2] = true

			tracker.Reset(ctx)

			// Length should always be defaultMaxObjectsPerPage.
			assert.Equal(t, defaultMaxObjectsPerPage, len(tracker.completedObjects),
				"Reset changed the length of completed objects")

			if tt.enabled {
				// All values should be false after reset.
				for i, isCompleted := range tracker.completedObjects {
					assert.False(t, isCompleted,
						"Reset did not clear completed object at index %d", i)
				}

				// Completion order should be empty.
				assert.Equal(t, 0, len(tracker.completionOrder),
					"Reset did not clear completion order")
			}
		})
	}
}

func TestGetResumePoint(t *testing.T) {
	tests := []struct {
		name               string
		enabled            bool
		progress           *sources.Progress
		expectedResumeInfo ResumeInfo
		expectError        bool
	}{
		{
			name:    "valid resume info",
			enabled: true,
			progress: &sources.Progress{
				EncodedResumeInfo: `{"current_bucket":"test-bucket","start_after":"test-key"}`,
			},
			expectedResumeInfo: ResumeInfo{CurrentBucket: "test-bucket", StartAfter: "test-key"},
		},
		{
			name:    "progress disabled",
			enabled: false,
			progress: &sources.Progress{
				EncodedResumeInfo: `{"current_bucket":"test-bucket","start_after":"test-key"}`,
			},
		},
		{
			name:     "empty encoded resume info",
			enabled:  true,
			progress: &sources.Progress{EncodedResumeInfo: ""},
		},
		{
			name:    "empty current bucket",
			enabled: true,
			progress: &sources.Progress{
				EncodedResumeInfo: `{"current_bucket":"","start_after":"test-key"}`,
			},
		},
		{
			name:               "nil progress",
			enabled:            true,
			progress:           nil,
			expectedResumeInfo: ResumeInfo{},
			expectError:        true,
		},
		{
			name:    "unmarshal error",
			enabled: true,
			progress: &sources.Progress{
				EncodedResumeInfo: `{"current_bucket":123,"start_after":"test-key"}`, // Invalid JSON
			},
			expectedResumeInfo: ResumeInfo{},
			expectError:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tracker := &ProgressTracker{enabled: tt.enabled, progress: tt.progress}

			resumePoint, err := tracker.GetResumePoint(context.Background())
			if tt.expectError {
				assert.Error(t, err, "Expected an error decoding resume info")
			} else {
				assert.NoError(t, err, "Expected no error decoding resume info")
			}

			assert.Equal(t, tt.expectedResumeInfo, resumePoint, "Unexpected resume point")
		})
	}
}

func setupTestTracker(t *testing.T, enabled bool, progress *sources.Progress, pageSize int) (*ProgressTracker, *s3.ListObjectsV2Output) {
	t.Helper()

	tracker := &ProgressTracker{
		enabled:          enabled,
		progress:         progress,
		completedObjects: make([]bool, pageSize),
		completionOrder:  make([]int, 0, pageSize),
	}
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

	err := tracker.UpdateObjectProgress(context.Background(), 1, "test-bucket", page.Contents)
	assert.NoError(t, err, "Error updating progress when tracker disabled")

	assert.Empty(t, progress.EncodedResumeInfo, "Progress updated when tracker disabled")
}

func TestProgressTrackerUpdateProgressCompletedIdxOOR(t *testing.T) {
	t.Parallel()

	progress := new(sources.Progress)
	tracker, page := setupTestTracker(t, true, progress, 5)

	err := tracker.UpdateObjectProgress(context.Background(), 1001, "test-bucket", page.Contents)
	assert.Error(t, err, "Expected error when completedIdx out of range")

	assert.Empty(t, progress.EncodedResumeInfo, "Progress updated when tracker disabled")
}

func TestProgressTrackerSequence(t *testing.T) {
	tests := []struct {
		name        string
		description string
		// Each update is a sequence of {completedIdx, expectedCompleted, expectedRemaining}
		updates  [][3]int
		pageSize int
	}{
		{
			name:        "multiple updates same page",
			description: "Verify remaining count isn't doubled and completed accumulates correctly",
			pageSize:    5,
			updates: [][3]int{
				{0, 1, 5}, // First object - should set remaining to 5
				{1, 2, 5}, // Second object - remaining should stay 5
				{2, 3, 5}, // Third object - remaining should stay 5
				{4, 3, 5}, // Gap at index 3 - completed should stay at 3
			},
		},
		{
			name:        "across page boundaries",
			description: "Verify completed count accumulates across pages",
			pageSize:    3,
			updates: [][3]int{
				// First page
				{0, 1, 3},
				{1, 2, 3},
				{2, 3, 3},
				// Reset and start new page.
				{0, 4, 6}, // baseCompleted(3) + current(1)
				{1, 5, 6}, // baseCompleted(3) + current(2)
				{2, 6, 6}, // baseCompleted(3) + current(3)
			},
		},
		{
			name:        "incomplete page transition",
			description: "Verify incomplete page properly sets base completed",
			pageSize:    4,
			updates: [][3]int{
				// First page - only complete first 2.
				{0, 1, 4},
				{1, 2, 4},
				// Skip 2,3 and move to next page.
				// Reset and start new page.
				{0, 3, 8}, // baseCompleted(2) + current(1)
				{1, 4, 8}, // baseCompleted(2) + current(2)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			progress := new(sources.Progress)
			tracker, page := setupTestTracker(t, true, progress, tt.pageSize)

			pageCount := 0
			for i, update := range tt.updates {
				completedIdx, expectedCompleted, expectedRemaining := update[0], update[1], update[2]

				// If this update starts a new page.
				if completedIdx == 0 && i > 0 {
					pageCount++
					tracker.Reset(ctx)
					// Create new page with same size.
					page = &s3.ListObjectsV2Output{Contents: make([]*s3.Object, tt.pageSize)}
					for j := range tt.pageSize {
						key := fmt.Sprintf("page%d-key-%d", pageCount, j)
						page.Contents[j] = &s3.Object{Key: &key}
					}
				}

				err := tracker.UpdateObjectProgress(ctx, completedIdx, "test-bucket", page.Contents)
				assert.NoError(t, err, "Unexpected error updating progress")

				assert.Equal(t, expectedCompleted, int(progress.SectionsCompleted),
					"Incorrect completed count at update %d", i)
				assert.Equal(t, expectedRemaining, int(progress.SectionsRemaining),
					"Incorrect remaining count at update %d", i)
			}
		})
	}
}

func TestProgressTrackerUpdateProgressWithResume(t *testing.T) {
	tests := []struct {
		name         string
		description  string
		completedIdx int
		pageSize     int
		preCompleted []int

		expectedKey       string
		expectedCompleted int
		expectedRemaining int
	}{
		{
			name:              "first object completed",
			description:       "Basic case - completing first object",
			completedIdx:      0,
			pageSize:          3,
			expectedKey:       "key-0",
			expectedCompleted: 1,
			expectedRemaining: 3,
		},
		{
			name:              "completing missing middle",
			description:       "Completing object when previous is done",
			completedIdx:      1,
			pageSize:          3,
			preCompleted:      []int{0},
			expectedKey:       "key-1",
			expectedCompleted: 2,
			expectedRemaining: 3,
		},
		{
			name:              "completing first with last done",
			description:       "Completing first object when last is already done",
			completedIdx:      0,
			pageSize:          3,
			preCompleted:      []int{2},
			expectedKey:       "key-0",
			expectedCompleted: 1,
			expectedRemaining: 3,
		},
		{
			name:              "all objects completed in order",
			description:       "Completing final object in sequence",
			completedIdx:      2,
			pageSize:          3,
			preCompleted:      []int{0, 1},
			expectedKey:       "key-2",
			expectedCompleted: 3,
			expectedRemaining: 3,
		},
		{
			name:              "completing middle gaps",
			description:       "Completing object with gaps in sequence",
			completedIdx:      5,
			pageSize:          10,
			preCompleted:      []int{0, 1, 2, 4},
			expectedKey:       "key-2",
			expectedCompleted: 3,
			expectedRemaining: 10,
		},
		{
			name:              "zero index with empty pre-completed",
			description:       "Edge case - minimum valid index",
			completedIdx:      0,
			pageSize:          1,
			expectedKey:       "key-0",
			expectedCompleted: 1,
			expectedRemaining: 1,
		},
		{
			name:         "last index in max page",
			description:  "Edge case - maximum page size boundary",
			completedIdx: 999,
			pageSize:     1000,
			preCompleted: func() []int {
				indices := make([]int, 999)
				for i := range 999 {
					indices[i] = i
				}
				return indices
			}(),
			expectedKey:       "key-999",
			expectedCompleted: 1000,
			expectedRemaining: 1000,
		},
		{
			name:         "all previous completed",
			description:  "Edge case - all previous indices completed",
			completedIdx: 100,
			pageSize:     101,
			preCompleted: func() []int {
				indices := make([]int, 100)
				for i := range 100 {
					indices[i] = i
				}
				return indices
			}(),
			expectedKey:       "key-100",
			expectedCompleted: 101,
			expectedRemaining: 101,
		},
		{
			name:              "large page number completion",
			description:       "Edge case - very large page number",
			completedIdx:      5,
			pageSize:          10,
			preCompleted:      []int{0, 1, 2, 3, 4},
			expectedKey:       "key-5",
			expectedCompleted: 6,
			expectedRemaining: 10,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			progress := new(sources.Progress)
			tracker, page := setupTestTracker(t, true, progress, tt.pageSize)

			// Apply pre-completed indices in order.
			if tt.preCompleted != nil {
				for _, idx := range tt.preCompleted {
					tracker.completedObjects[idx] = true
					tracker.completionOrder = append(tracker.completionOrder, idx)
				}
			}

			err := tracker.UpdateObjectProgress(ctx, tt.completedIdx, "test-bucket", page.Contents)
			assert.NoError(t, err, "Unexpected error updating progress")

			assert.NotEmpty(t, progress.EncodedResumeInfo, "Expected progress update")
			var info ResumeInfo
			err = json.Unmarshal([]byte(progress.EncodedResumeInfo), &info)
			assert.NoError(t, err, "Failed to decode resume info")
			assert.Equal(t, tt.expectedKey, info.StartAfter, "Incorrect resume point")

			assert.Equal(t, tt.expectedCompleted, int(progress.SectionsCompleted),
				"Incorrect completed count")
			assert.Equal(t, tt.expectedRemaining, int(progress.SectionsRemaining),
				"Incorrect remaining count")
		})
	}
}

func TestProgressTrackerUpdateProgressNoResume(t *testing.T) {
	tests := []struct {
		name         string
		description  string
		completedIdx int
		pageSize     int
		preCompleted map[int]bool
	}{
		{
			name:         "middle object completed first",
			description:  "Basic case - completing middle object first",
			completedIdx: 1,
			pageSize:     3,
		},
		{
			name:         "last object completed first",
			description:  "Basic case - completing last object first",
			completedIdx: 2,
			pageSize:     3,
		},
		{
			name:         "multiple gaps",
			description:  "Multiple non-consecutive completions",
			completedIdx: 5,
			pageSize:     10,
			preCompleted: map[int]bool{1: true, 3: true, 4: true},
		},
		{
			name:         "alternating completion pattern",
			description:  "Edge case - alternating completed/uncompleted pattern",
			completedIdx: 10,
			pageSize:     20,
			preCompleted: map[int]bool{2: true, 4: true, 6: true, 8: true},
		},
		{
			name:         "sparse completion pattern",
			description:  "Edge case - scattered completions with regular gaps",
			completedIdx: 50,
			pageSize:     100,
			preCompleted: map[int]bool{10: true, 20: true, 30: true, 40: true},
		},
		{
			name:         "single gap breaks sequence",
			description:  "Edge case - single gap prevents resume info",
			completedIdx: 50,
			pageSize:     100,
			preCompleted: func() map[int]bool {
				m := make(map[int]bool)
				for i := 1; i <= 49; i++ {
					m[i] = true
				}
				m[49] = false
				return m
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			progress := new(sources.Progress)
			enabled := tt.name != "disabled tracker"
			tracker, page := setupTestTracker(t, enabled, progress, tt.pageSize)

			if tt.preCompleted != nil {
				for k, v := range tt.preCompleted {
					tracker.completedObjects[k] = v
				}
			}

			err := tracker.UpdateObjectProgress(ctx, tt.completedIdx, "test-bucket", page.Contents)
			assert.NoError(t, err, "Unexpected error updating progress")
			assert.Empty(t, progress.EncodedResumeInfo, "Expected no progress update")
		})
	}
}

func TestComplete(t *testing.T) {
	tests := []struct {
		name         string
		enabled      bool
		initialState struct {
			sectionsCompleted uint64
			sectionsRemaining uint64
			resumeInfo        string
			message           string
		}
		completeMessage string
		wantState       struct {
			sectionsCompleted uint64
			sectionsRemaining uint64
			resumeInfo        string
			message           string
		}
	}{
		{
			name:    "marks completion with existing progress",
			enabled: true,
			initialState: struct {
				sectionsCompleted uint64
				sectionsRemaining uint64
				resumeInfo        string
				message           string
			}{
				sectionsCompleted: 100,
				sectionsRemaining: 100,
				resumeInfo:        `{"CurrentBucket":"test-bucket","StartAfter":"some-key"}`,
				message:           "In progress",
			},
			completeMessage: "Scan complete",
			wantState: struct {
				sectionsCompleted uint64
				sectionsRemaining uint64
				resumeInfo        string
				message           string
			}{
				sectionsCompleted: 100, // Should preserve existing progress
				sectionsRemaining: 100, // Should preserve existing progress
				resumeInfo:        "",  // Should clear resume info
				message:           "Scan complete",
			},
		},
		{
			name:    "disabled tracker",
			enabled: false,
			initialState: struct {
				sectionsCompleted uint64
				sectionsRemaining uint64
				resumeInfo        string
				message           string
			}{
				sectionsCompleted: 50,
				sectionsRemaining: 100,
				resumeInfo:        `{"CurrentBucket":"test-bucket","StartAfter":"some-key"}`,
				message:           "Should not change",
			},
			completeMessage: "Completed",
			wantState: struct {
				sectionsCompleted uint64
				sectionsRemaining uint64
				resumeInfo        string
				message           string
			}{
				sectionsCompleted: 50,
				sectionsRemaining: 100,
				resumeInfo:        `{"CurrentBucket":"test-bucket","StartAfter":"some-key"}`,
				message:           "Should not change",
			},
		},
		{
			name:    "completes with special characters",
			enabled: true,
			initialState: struct {
				sectionsCompleted uint64
				sectionsRemaining uint64
				resumeInfo        string
				message           string
			}{
				sectionsCompleted: 75,
				sectionsRemaining: 75,
				resumeInfo:        `{"CurrentBucket":"bucket","StartAfter":"key"}`,
				message:           "In progress",
			},
			completeMessage: "Completed scanning 特殊字符 & symbols !@#$%",
			wantState: struct {
				sectionsCompleted uint64
				sectionsRemaining uint64
				resumeInfo        string
				message           string
			}{
				sectionsCompleted: 75,
				sectionsRemaining: 75,
				resumeInfo:        "",
				message:           "Completed scanning 特殊字符 & symbols !@#$%",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			progress := &sources.Progress{
				SectionsCompleted: int32(tt.initialState.sectionsCompleted),
				SectionsRemaining: int32(tt.initialState.sectionsRemaining),
				EncodedResumeInfo: tt.initialState.resumeInfo,
				Message:           tt.initialState.message,
			}
			tracker := NewProgressTracker(ctx, tt.enabled, progress)

			err := tracker.Complete(ctx, tt.completeMessage)
			assert.NoError(t, err)

			assert.Equal(t, int32(tt.wantState.sectionsCompleted), progress.SectionsCompleted)
			assert.Equal(t, int32(tt.wantState.sectionsRemaining), progress.SectionsRemaining)
			assert.Equal(t, tt.wantState.resumeInfo, progress.EncodedResumeInfo)
			assert.Equal(t, tt.wantState.message, progress.Message)
		})
	}
}
