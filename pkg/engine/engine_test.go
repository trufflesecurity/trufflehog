package engine

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/decoders"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
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
	tests := []struct {
		name          string
		sourceType    sourcespb.SourceType
		expectedValue bool
	}{
		{"Git source", sourcespb.SourceType_SOURCE_TYPE_GIT, true},
		{"Github source", sourcespb.SourceType_SOURCE_TYPE_GITHUB, true},
		{"Gitlab source", sourcespb.SourceType_SOURCE_TYPE_GITLAB, true},
		{"Bitbucket source", sourcespb.SourceType_SOURCE_TYPE_BITBUCKET, true},
		{"Gerrit source", sourcespb.SourceType_SOURCE_TYPE_GERRIT, true},
		{"Github unauthenticated org source", sourcespb.SourceType_SOURCE_TYPE_GITHUB_UNAUTHENTICATED_ORG, true},
		{"Public Git source", sourcespb.SourceType_SOURCE_TYPE_PUBLIC_GIT, true},
		{"Filesystem source", sourcespb.SourceType_SOURCE_TYPE_FILESYSTEM, true},
		{"Azure Repos source", sourcespb.SourceType_SOURCE_TYPE_AZURE_REPOS, true},
		{"Unsupported type", sourcespb.SourceType_SOURCE_TYPE_BUILDKITE, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SupportsLineNumbers(tt.sourceType)
			assert.Equal(t, tt.expectedValue, result)
		})
	}
}

func BenchmarkSupportsLineNumbersLoop(b *testing.B) {
	sourceType := sourcespb.SourceType_SOURCE_TYPE_GITHUB
	for i := 0; i < b.N; i++ {
		_ = SupportsLineNumbers(sourceType)
	}
}

// TestEngine_DuplicatSecrets is a test that detects ALL duplicate secrets with the same decoder.
func TestEngine_DuplicatSecrets(t *testing.T) {
	ctx := context.Background()

	absPath, err := filepath.Abs("./testdata")
	assert.Nil(t, err)

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	e, err := Start(ctx,
		WithConcurrency(1),
		WithDecoders(decoders.DefaultDecoders()...),
		WithDetectors(true, DefaultDetectors()...),
		WithPrinter(new(discardPrinter)),
	)
	assert.Nil(t, err)

	cfg := sources.FilesystemConfig{Paths: []string{absPath}}
	if err := e.ScanFileSystem(ctx, cfg); err != nil {
		return
	}

	// Wait for all the chunks to be processed.
	assert.Nil(t, e.Finish(ctx))
	want := uint64(5)
	assert.Equal(t, want, e.GetMetrics().UnverifiedSecretsFound)
}

func TestFragmentFirstLineAndLink(t *testing.T) {
	tests := []struct {
		name         string
		chunk        *sources.Chunk
		expectedLine int64
		expectedLink string
	}{
		{
			name: "Test Git Metadata",
			chunk: &sources.Chunk{
				SourceMetadata: &source_metadatapb.MetaData{
					Data: &source_metadatapb.MetaData_Git{
						Git: &source_metadatapb.Git{
							Line: 10,
						},
					},
				},
			},
			expectedLine: 10,
			expectedLink: "", // Git doesn't support links
		},
		{
			name: "Test Github Metadata",
			chunk: &sources.Chunk{
				SourceMetadata: &source_metadatapb.MetaData{
					Data: &source_metadatapb.MetaData_Github{
						Github: &source_metadatapb.Github{
							Line: 5,
							Link: "https://example.github.com",
						},
					},
				},
			},
			expectedLine: 5,
			expectedLink: "https://example.github.com",
		},
		{
			name: "Test Azure Repos Metadata",
			chunk: &sources.Chunk{
				SourceMetadata: &source_metadatapb.MetaData{
					Data: &source_metadatapb.MetaData_AzureRepos{
						AzureRepos: &source_metadatapb.AzureRepos{
							Line: 5,
							Link: "https://example.azure.com",
						},
					},
				},
			},
			expectedLine: 5,
			expectedLink: "https://example.azure.com",
		},
		{
			name:         "Unsupported Type",
			chunk:        &sources.Chunk{},
			expectedLine: 0,
			expectedLink: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			line, linePtr, link := FragmentFirstLineAndLink(tt.chunk)
			assert.Equal(t, tt.expectedLink, link, "Mismatch in link")
			assert.Equal(t, tt.expectedLine, line, "Mismatch in line")

			if linePtr != nil {
				assert.Equal(t, tt.expectedLine, *linePtr, "Mismatch in linePtr value")
			}
		})
	}
}

func TestSetLink(t *testing.T) {
	tests := []struct {
		name     string
		input    *source_metadatapb.MetaData
		link     string
		line     int64
		wantLink string
		wantErr  bool
	}{
		{
			name: "Github link set",
			input: &source_metadatapb.MetaData{
				Data: &source_metadatapb.MetaData_Github{
					Github: &source_metadatapb.Github{},
				},
			},
			link:     "https://github.com/example",
			line:     42,
			wantLink: "https://github.com/example#L42",
		},
		{
			name: "Gitlab link set",
			input: &source_metadatapb.MetaData{
				Data: &source_metadatapb.MetaData_Gitlab{
					Gitlab: &source_metadatapb.Gitlab{},
				},
			},
			link:     "https://gitlab.com/example",
			line:     10,
			wantLink: "https://gitlab.com/example#L10",
		},
		{
			name: "Bitbucket link set",
			input: &source_metadatapb.MetaData{
				Data: &source_metadatapb.MetaData_Bitbucket{
					Bitbucket: &source_metadatapb.Bitbucket{},
				},
			},
			link:     "https://bitbucket.com/example",
			line:     8,
			wantLink: "https://bitbucket.com/example#L8",
		},
		{
			name: "Filesystem link set",
			input: &source_metadatapb.MetaData{
				Data: &source_metadatapb.MetaData_Filesystem{
					Filesystem: &source_metadatapb.Filesystem{},
				},
			},
			link:     "file:///path/to/example",
			line:     3,
			wantLink: "file:///path/to/example#L3",
		},
		{
			name: "Azure Repos link set",
			input: &source_metadatapb.MetaData{
				Data: &source_metadatapb.MetaData_AzureRepos{
					AzureRepos: &source_metadatapb.AzureRepos{},
				},
			},
			link:     "https://dev.azure.com/example",
			line:     3,
			wantLink: "https://dev.azure.com/example?line=3",
		},
		{
			name: "Unsupported metadata type",
			input: &source_metadatapb.MetaData{
				Data: &source_metadatapb.MetaData_Git{
					Git: &source_metadatapb.Git{},
				},
			},
			link:    "https://git.example.com/link",
			line:    5,
			wantErr: true,
		},
		{
			name:    "Metadata nil",
			input:   nil,
			link:    "https://some.link",
			line:    1,
			wantErr: true,
		},
	}

	ctx := context.Background()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := UpdateLink(ctx, tt.input, tt.link, tt.line)
			if err != nil && !tt.wantErr {
				t.Errorf("Unexpected error: %v", err)
			}

			if tt.wantErr {
				return
			}

			switch data := tt.input.GetData().(type) {
			case *source_metadatapb.MetaData_Github:
				assert.Equal(t, tt.wantLink, data.Github.Link, "Github link mismatch")
			case *source_metadatapb.MetaData_Gitlab:
				assert.Equal(t, tt.wantLink, data.Gitlab.Link, "Gitlab link mismatch")
			case *source_metadatapb.MetaData_Bitbucket:
				assert.Equal(t, tt.wantLink, data.Bitbucket.Link, "Bitbucket link mismatch")
			case *source_metadatapb.MetaData_Filesystem:
				assert.Equal(t, tt.wantLink, data.Filesystem.Link, "Filesystem link mismatch")
			case *source_metadatapb.MetaData_AzureRepos:
				assert.Equal(t, tt.wantLink, data.AzureRepos.Link, "Azure Repos link mismatch")
			}
		})
	}
}
