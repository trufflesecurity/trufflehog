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
		expectedBool bool
	}{
		{
			name: "trufflehog:ignore found",
			chunk: &sources.Chunk{
				Data: []byte("line1\nline2\ntrufflehog:ignore\nline4"),
			},
			result: &detectors.Result{
				Raw: []byte("trufflehog:ignore"),
			},
			expectedLine: 2,
			expectedBool: true,
		},
		{
			name: "nonexistent string",
			chunk: &sources.Chunk{
				Data: []byte("line1\nline2\ntrufflehog:ignore\nline4"),
			},
			result: &detectors.Result{
				Raw: []byte("nonexistent"),
			},
			expectedLine: 0,
			expectedBool: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lineOffset, isIgnored := FragmentLineOffset(tt.chunk, tt.result)
			if lineOffset != tt.expectedLine {
				t.Errorf("Expected line offset to be %d, got %d", tt.expectedLine, lineOffset)
			}
			if isIgnored != tt.expectedBool {
				t.Errorf("Expected isIgnored to be %v, got %v", tt.expectedBool, isIgnored)
			}
		})
	}
}
