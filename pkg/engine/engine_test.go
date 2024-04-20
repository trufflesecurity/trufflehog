package engine

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/custom_detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/decoders"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/custom_detectorspb"
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

	absPath, err := filepath.Abs("./testdata/secrets.txt")
	assert.Nil(t, err)

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	e, err := Start(ctx,
		WithConcurrency(1),
		WithDecoders(decoders.DefaultDecoders()...),
		WithDetectors(DefaultDetectors()...),
		WithVerify(false),
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

// TestEngine_VersionedDetectorsVerifiedSecrets is a test that detects ALL verified secrets across
// versioned detectors.
func TestEngine_VersionedDetectorsVerifiedSecrets(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	testSecrets, err := common.GetSecret(ctx, "trufflehog-testing", "detectors4")
	if err != nil {
		t.Log("Failed to get secrets, likely running community-tests")
		return
	}
	assert.NoError(t, err)
	secretV2 := testSecrets.MustGetField("GITLABV2")
	secretV1 := testSecrets.MustGetField("GITLAB")

	tmpFile, err := os.CreateTemp("", "testfile")
	assert.Nil(t, err)
	defer tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.WriteString(fmt.Sprintf("You can find a gitlab secrets %s and another gitlab secret %s within", secretV2, secretV1))
	assert.Nil(t, err)

	e, err := Start(ctx,
		WithConcurrency(1),
		WithDecoders(decoders.DefaultDecoders()...),
		WithDetectors(DefaultDetectors()...),
		WithVerify(true),
		WithPrinter(new(discardPrinter)),
	)
	assert.Nil(t, err)

	cfg := sources.FilesystemConfig{Paths: []string{tmpFile.Name()}}
	if err := e.ScanFileSystem(ctx, cfg); err != nil {
		return
	}

	assert.Nil(t, e.Finish(ctx))
	want := uint64(2)
	assert.Equal(t, want, e.GetMetrics().VerifiedSecretsFound)
}

// TestEngine_CustomDetectorsDetectorsVerifiedSecrets is a test that covers an edge case where there are
// multiple detectors with the same type, keywords and regex that match the same secret.
// This ensures that those secrets get verified.
func TestEngine_CustomDetectorsDetectorsVerifiedSecrets(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "testfile")
	assert.Nil(t, err)
	defer tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.WriteString("test stuff")
	assert.Nil(t, err)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	customDetector1, err := custom_detectors.NewWebhookCustomRegex(&custom_detectorspb.CustomRegex{
		Name:     "custom detector 1",
		Keywords: []string{"test"},
		Regex:    map[string]string{"test": "\\w+"},
		Verify:   []*custom_detectorspb.VerifierConfig{{Endpoint: ts.URL, Unsafe: true, SuccessRanges: []string{"200"}}},
	})
	assert.Nil(t, err)

	customDetector2, err := custom_detectors.NewWebhookCustomRegex(&custom_detectorspb.CustomRegex{
		Name:     "custom detector 2",
		Keywords: []string{"test"},
		Regex:    map[string]string{"test": "\\w+"},
		Verify:   []*custom_detectorspb.VerifierConfig{{Endpoint: ts.URL, Unsafe: true, SuccessRanges: []string{"200"}}},
	})
	assert.Nil(t, err)

	allDetectors := []detectors.Detector{customDetector1, customDetector2}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	e, err := Start(ctx,
		WithConcurrency(1),
		WithDecoders(decoders.DefaultDecoders()...),
		WithDetectors(allDetectors...),
		WithVerify(true),
		WithPrinter(new(discardPrinter)),
	)
	assert.Nil(t, err)

	cfg := sources.FilesystemConfig{Paths: []string{tmpFile.Name()}}
	if err := e.ScanFileSystem(ctx, cfg); err != nil {
		return
	}

	assert.Nil(t, e.Finish(ctx))
	// We should have 4 verified secrets, 2 for each custom detector.
	want := uint64(4)
	assert.Equal(t, want, e.GetMetrics().VerifiedSecretsFound)
}

func TestVerificationOverlapChunk(t *testing.T) {
	ctx := context.Background()

	absPath, err := filepath.Abs("./testdata/verificationoverlap_secrets.txt")
	assert.Nil(t, err)

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	confPath, err := filepath.Abs("./testdata/verificationoverlap_detectors.yaml")
	assert.Nil(t, err)
	conf, err := config.Read(confPath)
	assert.Nil(t, err)

	e, err := Start(ctx,
		WithConcurrency(1),
		WithDecoders(decoders.DefaultDecoders()...),
		WithDetectors(conf.Detectors...),
		WithVerify(false),
		WithPrinter(new(discardPrinter)),
		withVerificationOverlapTracking(),
	)
	assert.Nil(t, err)

	cfg := sources.FilesystemConfig{Paths: []string{absPath}}
	if err := e.ScanFileSystem(ctx, cfg); err != nil {
		return
	}

	// Wait for all the chunks to be processed.
	assert.Nil(t, e.Finish(ctx))
	// We want TWO secrets that match both the custom regexes.
	want := uint64(2)
	assert.Equal(t, want, e.GetMetrics().UnverifiedSecretsFound)

	// We want 0 because these are custom detectors and verification should still occur.
	wantDupe := 0
	assert.Equal(t, wantDupe, e.verificationOverlapTracker.verificationOverlapDuplicateCount)
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

func TestLikelyDuplicate(t *testing.T) {
	// Initialize detectors
	// (not actually calling detector FromData or anything, just using detector struct for key creation)
	detectorA := ahocorasick.DetectorInfo{
		Key:      ahocorasick.CreateDetectorKey(DefaultDetectors()[0]),
		Detector: DefaultDetectors()[0],
	}
	detectorB := ahocorasick.DetectorInfo{
		Key:      ahocorasick.CreateDetectorKey(DefaultDetectors()[1]),
		Detector: DefaultDetectors()[1],
	}

	// Define test cases
	tests := []struct {
		name     string
		val      chunkSecretKey
		dupes    map[chunkSecretKey]struct{}
		expected bool
	}{
		{
			name: "exact duplicate different detector",
			val:  chunkSecretKey{"PMAK-qnwfsLyRSyfCwfpHaQP1UzDhrgpWvHjbYzjpRCMshjt417zWcrzyHUArs7r", detectorA.Key},
			dupes: map[chunkSecretKey]struct{}{
				{"PMAK-qnwfsLyRSyfCwfpHaQP1UzDhrgpWvHjbYzjpRCMshjt417zWcrzyHUArs7r", detectorB.Key}: {},
			},
			expected: true,
		},
		{
			name: "non-duplicate length outside range",
			val:  chunkSecretKey{"short", detectorA.Key},
			dupes: map[chunkSecretKey]struct{}{
				{"muchlongerthanthevalstring", detectorB.Key}: {},
			},
			expected: false,
		},
		{
			name: "similar within threshold",
			val:  chunkSecretKey{"PMAK-qnwfsLyRSyfCwfpHaQP1UzDhrgpWvHjbYzjpRCMshjt417zWcrzyHUArs7r", detectorA.Key},
			dupes: map[chunkSecretKey]struct{}{
				{"qnwfsLyRSyfCwfpHaQP1UzDhrgpWvHjbYzjpRCMshjt417zWcrzyHUArs7r", detectorB.Key}: {},
			},
			expected: true,
		},
		{
			name: "similar outside threshold",
			val:  chunkSecretKey{"anotherkey", detectorA.Key},
			dupes: map[chunkSecretKey]struct{}{
				{"completelydifferent", detectorB.Key}: {},
			},
			expected: false,
		},
		{
			name:     "empty strings",
			val:      chunkSecretKey{"", detectorA.Key},
			dupes:    map[chunkSecretKey]struct{}{{"", detectorB.Key}: {}},
			expected: true,
		},
		{
			name: "similar within threshold same detector",
			val:  chunkSecretKey{"PMAK-qnwfsLyRSyfCwfpHaQP1UzDhrgpWvHjbYzjpRCMshjt417zWcrzyHUArs7r", detectorA.Key},
			dupes: map[chunkSecretKey]struct{}{
				{"qnwfsLyRSyfCwfpHaQP1UzDhrgpWvHjbYzjpRCMshjt417zWcrzyHUArs7r", detectorA.Key}: {},
			},
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			result := likelyDuplicate(ctx, tc.val, tc.dupes)
			if result != tc.expected {
				t.Errorf("expected %v, got %v", tc.expected, result)
			}
		})
	}
}
