package engine

import (
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

func TestFragmentLineOffset(t *testing.T) {
	tests := []struct {
		name         string
		chunk        *sources.Chunk
		result       *detectors.Result
		expectedLine int64
		ignore       bool
	}{
		{
			name: "ignore found on same line",
			chunk: &sources.Chunk{
				Data: []byte("line1\nline2\nsecret here trufflehog:ignore\nline4"),
			},
			result: &detectors.Result{
				Raw: []byte("secret here"),
			},
			expectedLine: 2,
			ignore:       true,
		},
		{
			name: "no ignore",
			chunk: &sources.Chunk{
				Data: []byte("line1\nline2\nsecret here\nline4"),
			},
			result: &detectors.Result{
				Raw: []byte("secret here"),
			},
			expectedLine: 2,
			ignore:       false,
		},
		{
			name: "ignore on different line",
			chunk: &sources.Chunk{
				Data: []byte("line1\nline2\ntrufflehog:ignore\nline4\nsecret here\nline6"),
			},
			result: &detectors.Result{
				Raw: []byte("secret here"),
			},
			expectedLine: 4,
			ignore:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lineOffset, isIgnored := FragmentLineOffset(tt.chunk, tt.result)
			if lineOffset != tt.expectedLine {
				t.Errorf("Expected line offset to be %d, got %d", tt.expectedLine, lineOffset)
			}
			if isIgnored != tt.ignore {
				t.Errorf("Expected isIgnored to be %v, got %v", tt.ignore, isIgnored)
			}
		})
	}
}
