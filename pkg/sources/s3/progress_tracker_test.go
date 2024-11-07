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

			if !tt.enabled {
				assert.Equal(t, defaultMaxObjectsPerPage, len(tracker.completedObjects), "Reset did not clear completed objects")
				return
			}

			assert.Equal(t, 0, len(tracker.completedObjects), "Reset did not clear completed objects")
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

	tracker := NewProgressTracker(context.Background(), enabled, progress)
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

	err := tracker.UpdateObjectProgress(context.Background(), 1, "test-bucket", page.Contents, 1)
	assert.NoError(t, err, "Error updating progress when tracker disabled")

	assert.Empty(t, progress.EncodedResumeInfo, "Progress updated when tracker disabled")
}

func TestProgressTrackerUpdateProgressCompletedIdxOOR(t *testing.T) {
	t.Parallel()

	progress := new(sources.Progress)
	tracker, page := setupTestTracker(t, true, progress, 5)

	err := tracker.UpdateObjectProgress(context.Background(), 1001, "test-bucket", page.Contents, 1)
	assert.Error(t, err, "Expected error when completedIdx out of range")

	assert.Empty(t, progress.EncodedResumeInfo, "Progress updated when tracker disabled")
}

func TestProgressTrackerUpdateProgressWithResume(t *testing.T) {
	tests := []struct {
		name         string
		description  string // documents test purpose
		completedIdx int
		pageSize     int
		preCompleted map[int]bool
		pageNumber   int
		expectedKey  string // key we expect to be set in resume info
	}{
		{
			name:         "first object completed",
			description:  "Basic case - completing first object",
			completedIdx: 0,
			pageSize:     3,
			pageNumber:   1,
			expectedKey:  "key-0",
		},
		{
			name:         "completing missing middle",
			description:  "Completing object when previous is done",
			completedIdx: 1,
			pageSize:     3,
			preCompleted: map[int]bool{0: true},
			pageNumber:   1,
			expectedKey:  "key-1",
		},
		{
			name:         "completing first with last done",
			description:  "Completing first object when last is already done",
			completedIdx: 0,
			pageSize:     3,
			preCompleted: map[int]bool{2: true},
			pageNumber:   1,
			expectedKey:  "key-0",
		},
		{
			name:         "all objects completed in order",
			description:  "Completing final object in sequence",
			completedIdx: 2,
			pageSize:     3,
			preCompleted: map[int]bool{0: true, 1: true},
			pageNumber:   1,
			expectedKey:  "key-2",
		},
		{
			name:         "completing middle gaps",
			description:  "Completing object with gaps in sequence",
			completedIdx: 5,
			pageSize:     10,
			preCompleted: map[int]bool{0: true, 1: true, 2: true, 4: true},
			pageNumber:   1,
			expectedKey:  "key-2",
		},
		{
			name:         "zero index with empty pre-completed",
			description:  "Edge case - minimum valid index",
			completedIdx: 0,
			pageSize:     1,
			pageNumber:   1,
			expectedKey:  "key-0",
		},
		{
			name:         "last index in max page",
			description:  "Edge case - maximum page size boundary",
			completedIdx: 999,
			pageSize:     1000,
			preCompleted: func() map[int]bool {
				m := make(map[int]bool)
				for i := range 1000 {
					m[i] = true
				}
				return m
			}(),
			pageNumber:  1,
			expectedKey: "key-999",
		},
		{
			name:         "all previous completed",
			description:  "Edge case - all previous indices completed",
			completedIdx: 100,
			pageSize:     101,
			preCompleted: func() map[int]bool {
				m := make(map[int]bool)
				for i := range 100 {
					m[i] = true
				}
				return m
			}(),
			pageNumber:  1,
			expectedKey: "key-100",
		},
		{
			name:         "large page number completion",
			description:  "Edge case - very large page number",
			completedIdx: 5,
			pageSize:     10,
			preCompleted: map[int]bool{0: true, 1: true, 2: true, 3: true, 4: true},
			pageNumber:   999999,
			expectedKey:  "key-5",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			progress := new(sources.Progress)
			tracker, page := setupTestTracker(t, true, progress, tt.pageSize)

			if tt.preCompleted != nil {
				for k, v := range tt.preCompleted {
					tracker.completedObjects[k] = v
				}
			}

			err := tracker.UpdateObjectProgress(ctx, tt.completedIdx, "test-bucket", page.Contents, tt.pageNumber)
			assert.NoError(t, err, "Unexpected error updating progress")

			assert.NotEmpty(t, progress.EncodedResumeInfo, "Expected progress update")
			var info ResumeInfo
			err = json.Unmarshal([]byte(progress.EncodedResumeInfo), &info)
			assert.NoError(t, err, "Failed to decode resume info")
			assert.Equal(t, tt.expectedKey, info.StartAfter, "Incorrect resume point")
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
		pageNumber   int
	}{
		{
			name:         "middle object completed first",
			description:  "Basic case - completing middle object first",
			completedIdx: 1,
			pageSize:     3,
			pageNumber:   1,
		},
		{
			name:         "last object completed first",
			description:  "Basic case - completing last object first",
			completedIdx: 2,
			pageSize:     3,
			pageNumber:   1,
		},
		{
			name:         "multiple gaps",
			description:  "Multiple non-consecutive completions",
			completedIdx: 5,
			pageSize:     10,
			preCompleted: map[int]bool{1: true, 3: true, 4: true},
			pageNumber:   1,
		},
		{
			name:         "alternating completion pattern",
			description:  "Edge case - alternating completed/uncompleted pattern",
			completedIdx: 10,
			pageSize:     20,
			preCompleted: map[int]bool{2: true, 4: true, 6: true, 8: true},
			pageNumber:   1,
		},
		{
			name:         "sparse completion pattern",
			description:  "Edge case - scattered completions with regular gaps",
			completedIdx: 50,
			pageSize:     100,
			preCompleted: map[int]bool{10: true, 20: true, 30: true, 40: true},
			pageNumber:   1,
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
			pageNumber: 1,
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

			err := tracker.UpdateObjectProgress(ctx, tt.completedIdx, "test-bucket", page.Contents, tt.pageNumber)
			assert.NoError(t, err, "Unexpected error updating progress")
			assert.Empty(t, progress.EncodedResumeInfo, "Expected no progress update")
		})
	}
}

func TestUpdateScanProgress(t *testing.T) {
	tests := []struct {
		name        string
		enabled     bool
		currentIdx  int
		total       int
		message     string
		resumeInfo  ResumeInfo
		expectError bool
	}{
		{
			name:       "basic progress update",
			enabled:    true,
			currentIdx: 50,
			total:      100,
			message:    "Processing bucket contents",
			resumeInfo: ResumeInfo{CurrentBucket: "test-bucket", StartAfter: "key-50"},
		},
		{
			name:       "zero values",
			enabled:    true,
			currentIdx: 0,
			total:      0,
			message:    "",
			resumeInfo: ResumeInfo{},
		},
		{
			name:       "disabled tracker",
			enabled:    false,
			currentIdx: 25,
			total:      50,
			message:    "Should not update",
			resumeInfo: ResumeInfo{CurrentBucket: "test-bucket", StartAfter: "key-25"},
		},
		{
			name:       "max values",
			enabled:    true,
			currentIdx: 999999,
			total:      1000000,
			message:    "Processing large dataset",
			resumeInfo: ResumeInfo{CurrentBucket: "large-bucket", StartAfter: "key-999999"},
		},
		{
			name:       "special characters in message",
			enabled:    true,
			currentIdx: 10,
			total:      20,
			message:    "Processing 特殊字符 & symbols !@#$%",
			resumeInfo: ResumeInfo{CurrentBucket: "test-bucket", StartAfter: "key-with-特殊字符"},
		},
		{
			name:       "current greater than total",
			enabled:    true,
			currentIdx: 100,
			total:      50,
			message:    "Invalid progress state",
			resumeInfo: ResumeInfo{CurrentBucket: "test-bucket", StartAfter: "last-key"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			progress := new(sources.Progress)
			tracker := NewProgressTracker(ctx, tt.enabled, progress)

			err := tracker.UpdateScanProgress(ctx, tt.currentIdx, tt.total, tt.message, tt.resumeInfo)
			if tt.expectError {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)

			if !tt.enabled {
				assert.Empty(t, progress.EncodedResumeInfo)
				assert.Zero(t, progress.SectionsRemaining)
				assert.Zero(t, progress.SectionsCompleted)
				assert.Empty(t, progress.Message)
				return
			}

			assert.Equal(t, tt.currentIdx, int(progress.SectionsCompleted))
			assert.Equal(t, tt.total, int(progress.SectionsRemaining))
			assert.Equal(t, tt.message, progress.Message)

			var decodedInfo ResumeInfo
			err = json.Unmarshal([]byte(progress.EncodedResumeInfo), &decodedInfo)
			assert.NoError(t, err)
			assert.Equal(t, tt.resumeInfo, decodedInfo)
		})
	}
}
