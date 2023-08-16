package engine

import (
	"fmt"
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/decoders"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
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
		{
			name: "match on consecutive lines",
			chunk: &sources.Chunk{
				Data: []byte("line1\nline2\ntrufflehog:ignore\nline4\nsecret\nhere\nline6"),
			},
			result: &detectors.Result{
				Raw: []byte("secret\nhere"),
			},
			expectedLine: 4,
			ignore:       false,
		},
		{
			name: "ignore on last consecutive lines",
			chunk: &sources.Chunk{
				Data: []byte("line1\nline2\nline3\nsecret\nhere // trufflehog:ignore\nline5"),
			},
			result: &detectors.Result{
				Raw: []byte("secret\nhere"),
			},
			expectedLine: 3,
			ignore:       true,
		},
		{
			name: "ignore on last line",
			chunk: &sources.Chunk{
				Data: []byte("line1\nline2\nline3\nsecret here // trufflehog:ignore"),
			},
			result: &detectors.Result{
				Raw: []byte("secret here"),
			},
			expectedLine: 3,
			ignore:       true,
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

func setupFragmentLineOffsetBench(totalLines, needleLine int) (*sources.Chunk, *detectors.Result) {
	data := make([]byte, 0, 4096)
	needle := []byte("needle")
	for i := 0; i < totalLines; i++ {
		if i != needleLine {
			data = append(data, []byte(fmt.Sprintf("line%d\n", i))...)
			continue
		}
		data = append(data, needle...)
		data = append(data, '\n')
	}
	chunk := &sources.Chunk{Data: data}
	result := &detectors.Result{Raw: needle}
	return chunk, result
}

func BenchmarkFragmentLineOffsetStart(b *testing.B) {
	chunk, result := setupFragmentLineOffsetBench(512, 2)
	for i := 0; i < b.N; i++ {
		_, _ = FragmentLineOffset(chunk, result)
	}
}

func BenchmarkFragmentLineOffsetMiddle(b *testing.B) {
	chunk, result := setupFragmentLineOffsetBench(512, 256)
	for i := 0; i < b.N; i++ {
		_, _ = FragmentLineOffset(chunk, result)
	}
}

func BenchmarkFragmentLineOffsetEnd(b *testing.B) {
	chunk, result := setupFragmentLineOffsetBench(512, 510)
	for i := 0; i < b.N; i++ {
		_, _ = FragmentLineOffset(chunk, result)
	}
}

// Test to make sure that DefaultDecoders always returns the UTF8 decoder first.
// Technically a decoder test but we want this to run and fail in CI
func TestDefaultDecoders(t *testing.T) {
	ds := decoders.DefaultDecoders()
	if _, ok := ds[0].(*decoders.UTF8); !ok {
		t.Errorf("DefaultDecoders() = %v, expected UTF8 decoder to be first", ds)
	}
}

func TestSupportsLineNumbers(t *testing.T) {
	testCases := []struct {
		name     string
		input    sourcespb.SourceType
		expected bool
	}{
		{"Git source type", sourcespb.SourceType_SOURCE_TYPE_GIT, true},
		{"Github source type", sourcespb.SourceType_SOURCE_TYPE_GITHUB, true},
		{"Gitlab source type", sourcespb.SourceType_SOURCE_TYPE_GITLAB, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if result := SupportsLineNumbers(tc.input); result != tc.expected {
				t.Errorf("Expected %v for input %v, got %v", tc.expected, tc.input, result)
			}
		})
	}
}

func BenchmarkSupportsLineNumbersLoop(b *testing.B) {
	sourceType := sourcespb.SourceType_SOURCE_TYPE_GITHUB
	for i := 0; i < b.N; i++ {
		_ = SupportsLineNumbers(sourceType)
	}
}
