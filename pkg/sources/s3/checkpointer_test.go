package s3

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

func TestCheckpointerResumption(t *testing.T) {
	ctx := context.Background()

	// First scan - process 6 objects then interrupt.
	initialProgress := &sources.Progress{}
	tracker := NewCheckpointer(ctx, true, initialProgress)

	firstPage := &s3.ListObjectsV2Output{
		Contents: make([]*s3.Object, 12), // Total of 12 objects
	}
	for i := range 12 {
		key := fmt.Sprintf("key-%d", i)
		firstPage.Contents[i] = &s3.Object{Key: &key}
	}

	// Process first 6 objects.
	for i := range 6 {
		err := tracker.UpdateObjectCompletion(ctx, i, "test-bucket", firstPage.Contents)
		assert.NoError(t, err)
	}

	// Verify resume info is set correctly.
	resumeInfo, err := tracker.ResumePoint(ctx)
	require.NoError(t, err)
	assert.Equal(t, "test-bucket", resumeInfo.CurrentBucket)
	assert.Equal(t, "key-5", resumeInfo.StartAfter)

	// Resume scan with existing progress.
	resumeTracker := NewCheckpointer(ctx, true, initialProgress)

	resumePage := &s3.ListObjectsV2Output{
		Contents: firstPage.Contents[6:], // Remaining 6 objects
	}

	// Process remaining objects.
	for i := range len(resumePage.Contents) {
		err := resumeTracker.UpdateObjectCompletion(ctx, i, "test-bucket", resumePage.Contents)
		assert.NoError(t, err)
	}

	// Verify final resume info.
	finalResumeInfo, err := resumeTracker.ResumePoint(ctx)
	require.NoError(t, err)
	assert.Equal(t, "test-bucket", finalResumeInfo.CurrentBucket)
	assert.Equal(t, "key-11", finalResumeInfo.StartAfter)
}

func TestCheckpointerReset(t *testing.T) {
	tests := []struct {
		name    string
		enabled bool
	}{
		{name: "reset with enabled tracker", enabled: true},
		{name: "reset with disabled tracker", enabled: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			progress := new(sources.Progress)
			tracker := NewCheckpointer(ctx, tt.enabled, progress)

			tracker.completedObjects[1] = true
			tracker.completedObjects[2] = true

			tracker.Reset()

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

			tracker := &Checkpointer{enabled: tt.enabled, progress: tt.progress}

			resumePoint, err := tracker.ResumePoint(context.Background())
			if tt.expectError {
				assert.Error(t, err, "Expected an error decoding resume info")
			} else {
				assert.NoError(t, err, "Expected no error decoding resume info")
			}

			assert.Equal(t, tt.expectedResumeInfo, resumePoint, "Unexpected resume point")
		})
	}
}

func TestCheckpointerUpdate(t *testing.T) {
	tests := []struct {
		name                     string
		description              string
		completedIdx             int
		pageSize                 int
		preCompleted             []int
		expectedKey              string
		expectedLowestIncomplete int
	}{
		{
			name:                     "first object completed",
			description:              "Basic case - completing first object",
			completedIdx:             0,
			pageSize:                 3,
			expectedKey:              "key-0",
			expectedLowestIncomplete: 1,
		},
		{
			name:                     "completing missing middle",
			description:              "Completing object when previous is done",
			completedIdx:             1,
			pageSize:                 3,
			preCompleted:             []int{0},
			expectedKey:              "key-1",
			expectedLowestIncomplete: 2,
		},
		{
			name:                     "all objects completed in order",
			description:              "Completing final object in sequence",
			completedIdx:             2,
			pageSize:                 3,
			preCompleted:             []int{0, 1},
			expectedKey:              "key-2",
			expectedLowestIncomplete: 3,
		},
		{
			name:                     "out of order completion before lowest",
			description:              "Completing object before current lowest incomplete - should not affect checkpoint",
			completedIdx:             1,
			pageSize:                 4,
			preCompleted:             []int{0, 2, 3},
			expectedKey:              "key-3",
			expectedLowestIncomplete: 4,
		},
		{
			name:         "last index in max page",
			description:  "Edge case - maximum page size boundary",
			completedIdx: 999,
			pageSize:     1000,
			preCompleted: func() []int {
				indices := make([]int, 999)
				for i := range indices {
					indices[i] = i
				}
				return indices
			}(),
			expectedKey:              "key-999",
			expectedLowestIncomplete: 1000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			progress := new(sources.Progress)
			tracker := &Checkpointer{
				enabled:             true,
				progress:            progress,
				completedObjects:    make([]bool, tt.pageSize),
				completionOrder:     make([]int, 0, tt.pageSize),
				lowestIncompleteIdx: 0,
			}

			page := &s3.ListObjectsV2Output{Contents: make([]*s3.Object, tt.pageSize)}
			for i := range tt.pageSize {
				key := fmt.Sprintf("key-%d", i)
				page.Contents[i] = &s3.Object{Key: &key}
			}

			// Setup pre-completed objects.
			for _, idx := range tt.preCompleted {
				tracker.completedObjects[idx] = true
				tracker.completionOrder = append(tracker.completionOrder, idx)
			}

			// Find the correct lowest incomplete index after pre-completion.
			for i := range tt.pageSize {
				if !tracker.completedObjects[i] {
					tracker.lowestIncompleteIdx = i
					break
				}
			}

			err := tracker.UpdateObjectCompletion(ctx, tt.completedIdx, "test-bucket", page.Contents)
			assert.NoError(t, err, "Unexpected error updating progress")

			var info ResumeInfo
			err = json.Unmarshal([]byte(progress.EncodedResumeInfo), &info)
			assert.NoError(t, err, "Failed to decode resume info")
			assert.Equal(t, tt.expectedKey, info.StartAfter, "Incorrect resume point")

			assert.Equal(t, tt.expectedLowestIncomplete, tracker.lowestIncompleteIdx,
				"Incorrect lowest incomplete index")
		})
	}
}

func TestComplete(t *testing.T) {
	tests := []struct {
		name         string
		enabled      bool
		initialState struct {
			resumeInfo string
			message    string
		}
		completeMessage string
		wantState       struct {
			resumeInfo string
			message    string
		}
	}{
		{
			name:    "marks completion with existing resume info",
			enabled: true,
			initialState: struct {
				resumeInfo string
				message    string
			}{
				resumeInfo: `{"current_bucket":"test-bucket","start_after":"some-key"}`,
				message:    "In progress",
			},
			completeMessage: "Scan complete",
			wantState: struct {
				resumeInfo string
				message    string
			}{
				resumeInfo: "", // Should clear resume info
				message:    "Scan complete",
			},
		},
		{
			name:    "disabled tracker",
			enabled: false,
			initialState: struct {
				resumeInfo string
				message    string
			}{
				resumeInfo: "",
				message:    "Should not change",
			},
			completeMessage: "Completed",
			wantState: struct {
				resumeInfo string
				message    string
			}{
				resumeInfo: "",
				message:    "Completed",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			progress := &sources.Progress{
				EncodedResumeInfo: tt.initialState.resumeInfo,
				Message:           tt.initialState.message,
			}
			tracker := NewCheckpointer(ctx, tt.enabled, progress)

			err := tracker.Complete(ctx, tt.completeMessage)
			assert.NoError(t, err)

			assert.Equal(t, tt.wantState.resumeInfo, progress.EncodedResumeInfo)
			assert.Equal(t, tt.wantState.message, progress.Message)
		})
	}
}
