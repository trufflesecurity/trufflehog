package engine

import (
	aCtx "context"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/config"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/custom_detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/decoders"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/gitlab/v2"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/defaults"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/custom_detectorspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/verificationcache"
)

const fakeDetectorKeyword = "fakedetector"

type fakeDetectorV1 struct{}
type fakeDetectorV2 struct{}

var _ detectors.Detector = (*fakeDetectorV1)(nil)
var _ detectors.Versioner = (*fakeDetectorV1)(nil)
var _ detectors.Detector = (*fakeDetectorV2)(nil)
var _ detectors.Versioner = (*fakeDetectorV2)(nil)

func (f fakeDetectorV1) FromData(_ aCtx.Context, _ bool, _ []byte) ([]detectors.Result, error) {
	return []detectors.Result{
		{
			DetectorType: detectorspb.DetectorType(-1),
			Verified:     true,
			Raw:          []byte("fake secret v1"),
		},
	}, nil
}

func (f fakeDetectorV1) Keywords() []string             { return []string{fakeDetectorKeyword} }
func (f fakeDetectorV1) Type() detectorspb.DetectorType { return detectorspb.DetectorType(-1) }
func (f fakeDetectorV1) Version() int                   { return 1 }

func (f fakeDetectorV1) Description() string { return "fake detector v1" }

func (f fakeDetectorV2) FromData(_ aCtx.Context, _ bool, _ []byte) ([]detectors.Result, error) {
	return []detectors.Result{
		{
			DetectorType: detectorspb.DetectorType(-1),
			Verified:     true,
			Raw:          []byte("fake secret v2"),
		},
	}, nil
}

func (f fakeDetectorV2) Keywords() []string             { return []string{fakeDetectorKeyword} }
func (f fakeDetectorV2) Type() detectorspb.DetectorType { return detectorspb.DetectorType(-1) }
func (f fakeDetectorV2) Version() int                   { return 2 }

func (f fakeDetectorV2) Description() string { return "fake detector v2" }

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

func TestFragmentLineOffsetWithPrimarySecret(t *testing.T) {
	primarySecretResult1 := &detectors.Result{
		Raw: []byte("id heresecret here"), // RAW has two secrets merged
	}

	primarySecretResult1.SetPrimarySecretValue("secret here") // set `secret here` as primary secret value for line number calculation

	primarySecretResult2 := &detectors.Result{
		Raw: []byte("idsecret"), // RAW has two secrets merged
	}

	tests := []struct {
		name         string
		chunk        *sources.Chunk
		result       *detectors.Result
		expectedLine int64
		ignore       bool
	}{
		{
			name: "primary secret line number - correct line number",
			chunk: &sources.Chunk{
				Data: []byte("line1\nline2\nid here\nsecret here\nline5"),
			},
			result:       primarySecretResult1,
			expectedLine: 3,
			ignore:       false,
		},
		{
			name: "no primary secret set - wrong line number",
			chunk: &sources.Chunk{
				Data: []byte("line1\nline2\nid\nsecret\nline5"),
			},
			result:       primarySecretResult2,
			expectedLine: 0,
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

func TestFragmentLineOffsetWithPrimarySecretMultiline(t *testing.T) {
	result := &detectors.Result{
		Raw: []byte("secret here"),
	}
	result.SetPrimarySecretValue("secret:\nsecret here")

	chunk := &sources.Chunk{
		Data: []byte("line1\nline2\nsecret:\nsecret here\nline5"),
	}
	lineOffset, isIgnored := FragmentLineOffset(chunk, result)
	assert.False(t, isIgnored)
	// offset 2 means line 3
	assert.Equal(t, int64(2), lineOffset)
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

// TestEngine_DuplicateSecrets is a test that detects ALL duplicate secrets with the same decoder.
func TestEngine_DuplicateSecrets(t *testing.T) {
	ctx := context.Background()

	absPath, err := filepath.Abs("./testdata/secrets.txt")
	assert.Nil(t, err)

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	const defaultOutputBufferSize = 64
	opts := []func(*sources.SourceManager){
		sources.WithSourceUnits(),
		sources.WithBufferedOutput(defaultOutputBufferSize),
	}

	sourceManager := sources.NewManager(opts...)

	conf := Config{
		Concurrency:   1,
		Decoders:      decoders.DefaultDecoders(),
		Detectors:     defaults.DefaultDetectors(),
		Verify:        false,
		SourceManager: sourceManager,
		Dispatcher:    NewPrinterDispatcher(new(discardPrinter)),
	}

	e, err := NewEngine(ctx, &conf)
	assert.NoError(t, err)

	e.Start(ctx)

	cfg := sources.FilesystemConfig{Paths: []string{absPath}}
	if _, err := e.ScanFileSystem(ctx, cfg); err != nil {
		return
	}

	// Wait for all the chunks to be processed.
	assert.Nil(t, e.Finish(ctx))
	want := uint64(2)
	assert.Equal(t, want, e.GetMetrics().UnverifiedSecretsFound)
}

// lineCaptureDispatcher is a test dispatcher that captures the line number
// of detected secrets. It implements the Dispatcher interface and is used
// to verify that the Engine correctly identifies and reports the line numbers
// where secrets are found in the source code.
type lineCaptureDispatcher struct{ line int64 }

func (d *lineCaptureDispatcher) Dispatch(_ context.Context, result detectors.ResultWithMetadata) error {
	d.line = result.SourceMetadata.GetFilesystem().GetLine()
	return nil
}

func TestEngineLineVariations(t *testing.T) {
	tests := []struct {
		name         string
		content      string
		expectedLine int64
	}{
		{
			name: "secret on first line",
			content: `AKIA2OGYBAH6STMMNXNN
aws_secret_access_key = 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`,
			expectedLine: 1,
		},
		{
			name: "secret after multiple newlines",
			content: `


AKIA2OGYBAH6STMMNXNN
aws_secret_access_key = 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`,
			expectedLine: 4,
		},
		{
			name: "secret with mixed whitespace before",
			content: `first line


AKIA2OGYBAH6STMMNXNN
aws_secret_access_key = 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`,
			expectedLine: 4,
		},
		{
			name: "secret with content after",
			content: `[default]
region = us-east-1
AKIA2OGYBAH6STMMNXNN
aws_secret_access_key = 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
more content
even more`,
			expectedLine: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			tmpFile, err := os.CreateTemp("", "test_aws_credentials")
			assert.NoError(t, err)
			defer os.Remove(tmpFile.Name())

			err = os.WriteFile(tmpFile.Name(), []byte(tt.content), os.ModeAppend)
			assert.NoError(t, err)

			const defaultOutputBufferSize = 64
			opts := []func(*sources.SourceManager){
				sources.WithSourceUnits(),
				sources.WithBufferedOutput(defaultOutputBufferSize),
			}

			sourceManager := sources.NewManager(opts...)
			lineCapturer := new(lineCaptureDispatcher)

			conf := Config{
				Concurrency:   1,
				Decoders:      decoders.DefaultDecoders(),
				Detectors:     defaults.DefaultDetectors(),
				Verify:        false,
				SourceManager: sourceManager,
				Dispatcher:    lineCapturer,
			}

			eng, err := NewEngine(ctx, &conf)
			assert.NoError(t, err)

			eng.Start(ctx)

			cfg := sources.FilesystemConfig{Paths: []string{tmpFile.Name()}}
			_, err = eng.ScanFileSystem(ctx, cfg)
			assert.NoError(t, err)

			assert.NoError(t, eng.Finish(ctx))
			want := uint64(1)
			assert.Equal(t, want, eng.GetMetrics().UnverifiedSecretsFound)
			assert.Equal(t, tt.expectedLine, lineCapturer.line)
		})
	}
}

// TestEngine_VersionedDetectorsVerifiedSecrets is a test that detects ALL verified secrets across
// versioned detectors.
func TestEngine_VersionedDetectorsVerifiedSecrets(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	tmpFile, err := os.CreateTemp("", "testfile")
	assert.Nil(t, err)
	defer tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.WriteString(fmt.Sprintf("test data using keyword %s", fakeDetectorKeyword))
	assert.NoError(t, err)

	const defaultOutputBufferSize = 64
	opts := []func(*sources.SourceManager){
		sources.WithSourceUnits(),
		sources.WithBufferedOutput(defaultOutputBufferSize),
	}

	sourceManager := sources.NewManager(opts...)

	conf := Config{
		Concurrency:   1,
		Decoders:      decoders.DefaultDecoders(),
		Detectors:     []detectors.Detector{new(fakeDetectorV1), new(fakeDetectorV2)},
		Verify:        true,
		SourceManager: sourceManager,
		Dispatcher:    NewPrinterDispatcher(new(discardPrinter)),
	}

	e, err := NewEngine(ctx, &conf)
	assert.NoError(t, err)

	e.Start(ctx)

	cfg := sources.FilesystemConfig{Paths: []string{tmpFile.Name()}}
	if _, err := e.ScanFileSystem(ctx, cfg); err != nil {
		return
	}

	assert.NoError(t, e.Finish(ctx))
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

	const defaultOutputBufferSize = 64
	opts := []func(*sources.SourceManager){
		sources.WithSourceUnits(),
		sources.WithBufferedOutput(defaultOutputBufferSize),
	}

	sourceManager := sources.NewManager(opts...)

	conf := Config{
		Concurrency:   1,
		Decoders:      decoders.DefaultDecoders(),
		Detectors:     allDetectors,
		Verify:        true,
		SourceManager: sourceManager,
		Dispatcher:    NewPrinterDispatcher(new(discardPrinter)),
	}

	e, err := NewEngine(ctx, &conf)
	assert.NoError(t, err)

	e.Start(ctx)

	cfg := sources.FilesystemConfig{Paths: []string{tmpFile.Name()}}
	if _, err := e.ScanFileSystem(ctx, cfg); err != nil {
		return
	}

	assert.Nil(t, e.Finish(ctx))
	// We should have 4 verified secrets, 2 for each custom detector.
	want := uint64(4)
	assert.Equal(t, want, e.GetMetrics().VerifiedSecretsFound)
}

func TestProcessResult_SourceSupportsLineNumbers_LinkUpdated(t *testing.T) {
	// Arrange: Create an engine
	e := Engine{results: make(chan detectors.ResultWithMetadata, 1)}

	// Arrange: Create a Chunk
	chunk := sources.Chunk{
		Data: []byte("abcde\nswordfish"),
		SourceMetadata: &source_metadatapb.MetaData{
			Data: &source_metadatapb.MetaData_Github{
				Github: &source_metadatapb.Github{
					Line: 1,
					Link: "https://github.com/org/repo/blob/abcdef/file.txt#L1",
				},
			},
		},
		SourceType: sourcespb.SourceType_SOURCE_TYPE_GIT,
	}

	// Arrange: Create a Result
	result := detectors.Result{
		Raw:      []byte("swordfish"),
		Verified: true,
	}

	// Act
	e.processResult(context.AddLogger(t.Context()), result, chunk, 0, "", nil)

	// Assert that the link has been correctly updated
	require.Len(t, e.results, 1)
	r := <-e.results
	assert.Equal(t, "https://github.com/org/repo/blob/abcdef/file.txt#L2", r.SourceMetadata.GetGithub().GetLink())
}

func TestProcessResult_IgnoreLinePresent_NothingGenerated(t *testing.T) {
	// Arrange: Create an engine
	e := Engine{results: make(chan detectors.ResultWithMetadata, 1)}

	// Arrange: Create a Chunk
	chunk := sources.Chunk{
		Data: []byte("swordfish trufflehog:ignore"),
		SourceMetadata: &source_metadatapb.MetaData{
			Data: &source_metadatapb.MetaData_Git{
				Git: &source_metadatapb.Git{
					Line: 1,
				},
			},
		},
		SourceType: sourcespb.SourceType_SOURCE_TYPE_GIT,
	}

	// Arrange: Create a Result
	result := detectors.Result{
		Raw:      []byte("swordfish"),
		Verified: true,
	}

	// Act
	e.processResult(context.AddLogger(t.Context()), result, chunk, 0, "", nil)

	// Assert that no results were generated
	assert.Empty(t, e.results)
}

func TestProcessResult_AllFieldsCopied(t *testing.T) {
	// Arrange: Create an engine
	e := Engine{results: make(chan detectors.ResultWithMetadata, 1)}

	// Arrange: Create a Chunk
	chunk := sources.Chunk{
		SourceName: "test source",
		SourceID:   1,
		JobID:      2,
		SecretID:   3,
		SourceMetadata: &source_metadatapb.MetaData{
			Data: &source_metadatapb.MetaData_Docker{
				Docker: &source_metadatapb.Docker{
					File:  "file",
					Image: "image",
					Layer: "layer",
					Tag:   "tag",
				},
			},
		},
		SourceType: sourcespb.SourceType_SOURCE_TYPE_DOCKER,
	}

	// Arrange: Create a Result
	result := detectors.Result{
		DetectorType: detectorspb.DetectorType(-1),
		ExtraData:    map[string]string{"key": "value"},
		Raw:          []byte("something"),
		RawV2:        []byte("something:else"),
		Redacted:     "someth***",
		Verified:     true,
	}

	// Act
	e.processResult(context.AddLogger(t.Context()), result, chunk, detectorspb.DecoderType_PLAIN, "a detector that detects", nil)

	// Assert that the single generated result has the correct fields
	require.Len(t, e.results, 1)
	r := <-e.results
	if diff := cmp.Diff(chunk.SourceMetadata, r.SourceMetadata, protocmp.Transform()); diff != "" {
		t.Errorf("metadata mismatch (-want +got):\n%s", diff)
	}
	assert.Equal(t, map[string]string{"key": "value"}, r.ExtraData)
	assert.Equal(t, []byte("something"), r.Raw)
	assert.Equal(t, []byte("something:else"), r.RawV2)
	assert.Equal(t, "someth***", r.Redacted)
	assert.True(t, r.Verified)
	assert.Equal(t, detectorspb.DetectorType(-1), r.DetectorType)
	assert.Equal(t, sources.SourceID(1), r.SourceID)
	assert.Equal(t, sources.JobID(2), r.JobID)
	assert.Equal(t, int64(3), r.SecretID)
	assert.Equal(t, "test source", r.SourceName)
	assert.Equal(t, sourcespb.SourceType_SOURCE_TYPE_DOCKER, r.SourceType)
	assert.Equal(t, detectorspb.DecoderType_PLAIN, r.DecoderType)
	assert.Equal(t, "a detector that detects", r.DetectorDescription)
}

func TestProcessResult_FalsePositiveFlagSetCorrectly(t *testing.T) {
	testcases := []struct {
		name                string
		verified            bool
		isFalsePositive     bool
		wantIsFalsePositive bool
	}{
		{
			name:                "unverified/false positive",
			verified:            false,
			isFalsePositive:     true,
			wantIsFalsePositive: true,
		},
		{
			name:                "unverified/not false positive",
			verified:            false,
			isFalsePositive:     false,
			wantIsFalsePositive: false,
		},
		{
			name:                "verified/false positive",
			verified:            true,
			isFalsePositive:     true,
			wantIsFalsePositive: false, // The false positive check should not be run for verified secrets
		},
		{
			name:                "verified/not false positive",
			verified:            true,
			isFalsePositive:     false,
			wantIsFalsePositive: false,
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange: Create an Engine
			e := Engine{results: make(chan detectors.ResultWithMetadata, 1)}

			// Arrange: Create a Result
			res := detectors.Result{
				Raw:      []byte("something not nil"), // The false positive check is not run when Raw is nil
				Verified: tt.verified,
			}

			// Arrange: Create the false positive check
			isFalsePositive := func(_ detectors.Result) (bool, string) { return tt.isFalsePositive, "" }

			// Act
			e.processResult(context.AddLogger(t.Context()), res, sources.Chunk{}, 0, "", isFalsePositive)

			// Assert that the single generated result has the correct false positive flag
			require.Len(t, e.results, 1)
			assert.Equal(t, tt.wantIsFalsePositive, (<-e.results).IsWordlistFalsePositive)
		})
	}
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

	const defaultOutputBufferSize = 64
	opts := []func(*sources.SourceManager){
		sources.WithSourceUnits(),
		sources.WithBufferedOutput(defaultOutputBufferSize),
	}

	sourceManager := sources.NewManager(opts...)

	c := Config{
		Concurrency:      1,
		Decoders:         decoders.DefaultDecoders(),
		Detectors:        conf.Detectors,
		IncludeDetectors: "904", // isolate this test to only the custom detectors provided
		Verify:           false,
		SourceManager:    sourceManager,
		Dispatcher:       NewPrinterDispatcher(new(discardPrinter)),
	}

	e, err := NewEngine(ctx, &c)
	assert.NoError(t, err)

	e.verificationOverlapTracker = &atomic.Int32{}

	e.Start(ctx)

	cfg := sources.FilesystemConfig{Paths: []string{absPath}}
	if _, err := e.ScanFileSystem(ctx, cfg); err != nil {
		return
	}

	// Wait for all the chunks to be processed.
	assert.Nil(t, e.Finish(ctx))
	// We want TWO secrets that match both the custom regexes.
	want := uint64(2)
	assert.Equal(t, want, e.GetMetrics().UnverifiedSecretsFound)

	// We want 0 because these are custom detectors and verification should still occur.
	wantDupe := int32(0)
	assert.Equal(t, wantDupe, e.verificationOverlapTracker.Load())
}

func TestEngine_FalsePositivesRetainedCorrectly(t *testing.T) {
	// Arrange: Generate the absolute path of the file to scan
	secretsPath, err := filepath.Abs("./testdata/verificationoverlap_secrets_fp.txt")
	require.NoError(t, err)

	testCases := []struct {
		name                      string
		detectors                 []detectors.Detector
		retainFalsePositives      bool
		wantUnverifiedSecretCount uint64
	}{
		{
			name: "no overlap, retain false positives",
			detectors: []detectors.Detector{
				passthroughDetector{detectorType: detectorspb.DetectorType(-1), keywords: []string{"sample"}},
			},
			retainFalsePositives:      true,
			wantUnverifiedSecretCount: 1,
		},
		{
			name: "no overlap, do not retain false positives",
			detectors: []detectors.Detector{
				passthroughDetector{detectorType: detectorspb.DetectorType(-1), keywords: []string{"sample"}},
			},
			retainFalsePositives:      false,
			wantUnverifiedSecretCount: 0,
		},
		{
			name: "overlap, retain false positives",
			detectors: []detectors.Detector{
				passthroughDetector{detectorType: detectorspb.DetectorType(-1), keywords: []string{"sample"}},
				passthroughDetector{detectorType: detectorspb.DetectorType(-2), keywords: []string{"ample"}},
			},
			retainFalsePositives:      true,
			wantUnverifiedSecretCount: 2,
		},
		{
			name: "overlap, do not retain false positives",
			detectors: []detectors.Detector{
				passthroughDetector{detectorType: detectorspb.DetectorType(-1), keywords: []string{"sample"}},
				passthroughDetector{detectorType: detectorspb.DetectorType(-2), keywords: []string{"ample"}},
			},
			retainFalsePositives:      false,
			wantUnverifiedSecretCount: 0,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.AddLogger(t.Context())

			// Arrange: Generate a base engine config
			engineConfig := Config{
				Concurrency:   1,
				Decoders:      decoders.DefaultDecoders(),
				Detectors:     tt.detectors,
				Dispatcher:    NewPrinterDispatcher(new(discardPrinter)),
				Results:       map[string]struct{}{"verified": {}, "unverified": {}, "unknown": {}},
				SourceManager: sources.NewManager(sources.WithSourceUnits()),
				Verify:        false,
			}

			// Arrange: Set the appropriate false positive flag
			if tt.retainFalsePositives {
				engineConfig.Results["filtered_unverified"] = struct{}{}
			}

			// Arrange: Create and start an engine
			e, err := NewEngine(ctx, &engineConfig)
			require.NoError(t, err)
			e.Start(ctx)

			// Act: Scan the file
			cfg := sources.FilesystemConfig{Paths: []string{secretsPath}}
			_, err = e.ScanFileSystem(ctx, cfg)
			require.NoError(t, err)
			require.NoError(t, e.Finish(ctx))

			// Assert that the unverified secret count was expected
			assert.Equal(t, tt.wantUnverifiedSecretCount, e.GetMetrics().UnverifiedSecretsFound)
		})
	}
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
			name: "Line number not set",
			chunk: &sources.Chunk{
				SourceMetadata: &source_metadatapb.MetaData{
					Data: &source_metadatapb.MetaData_Github{
						Github: &source_metadatapb.Github{
							Link: "https://example.github.com",
						},
					},
				},
			},
			expectedLine: 1,
			expectedLink: "https://example.github.com",
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
			wantLink: "https://dev.azure.com/example?line=3&lineEnd=4&lineStartColumn=1",
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
	detectorA := ahocorasick.DetectorMatch{
		Key:      ahocorasick.CreateDetectorKey(defaults.DefaultDetectors()[0]),
		Detector: defaults.DefaultDetectors()[0],
	}
	detectorB := ahocorasick.DetectorMatch{
		Key:      ahocorasick.CreateDetectorKey(defaults.DefaultDetectors()[1]),
		Detector: defaults.DefaultDetectors()[1],
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

type customCleaner struct {
	ignoreConfig bool
}

var _ detectors.CustomResultsCleaner = (*customCleaner)(nil)
var _ detectors.Detector = (*customCleaner)(nil)

func (c customCleaner) FromData(aCtx.Context, bool, []byte) ([]detectors.Result, error) {
	return []detectors.Result{}, nil
}

func (c customCleaner) Keywords() []string             { return []string{} }
func (c customCleaner) Type() detectorspb.DetectorType { return detectorspb.DetectorType(-1) }

func (customCleaner) Description() string { return "" }

func (c customCleaner) CleanResults([]detectors.Result) []detectors.Result {
	return []detectors.Result{}
}
func (c customCleaner) ShouldCleanResultsIrrespectiveOfConfiguration() bool { return c.ignoreConfig }

func TestFilterResults_CustomCleaner(t *testing.T) {
	testCases := []struct {
		name               string
		cleaningConfigured bool
		ignoreConfig       bool
		resultsToClean     []detectors.Result
		wantResults        []detectors.Result
	}{
		{
			name:               "respect config to clean",
			cleaningConfigured: true,
			ignoreConfig:       false,
			resultsToClean:     []detectors.Result{{}},
			wantResults:        []detectors.Result{},
		},
		{
			name:               "respect config to not clean",
			cleaningConfigured: false,
			ignoreConfig:       false,
			resultsToClean:     []detectors.Result{{}},
			wantResults:        []detectors.Result{{}},
		},
		{
			name:               "clean irrespective of config",
			cleaningConfigured: false,
			ignoreConfig:       true,
			resultsToClean:     []detectors.Result{{}},
			wantResults:        []detectors.Result{},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			match := ahocorasick.DetectorMatch{
				Detector: customCleaner{
					ignoreConfig: tt.ignoreConfig,
				},
			}
			engine := Engine{
				filterUnverified:     tt.cleaningConfigured,
				retainFalsePositives: true,
			}

			cleaned := engine.filterResults(context.Background(), &match, tt.resultsToClean)

			assert.ElementsMatch(t, tt.wantResults, cleaned)
		})
	}
}

func BenchmarkPopulateMatchingDetectors(b *testing.B) {
	allDetectors := defaults.DefaultDetectors()
	ac := ahocorasick.NewAhoCorasickCore(allDetectors)

	// Generate sample data with keywords from detectors.
	dataSize := 1 << 20 // 1 MB
	sampleData := generateRandomDataWithKeywords(dataSize, allDetectors)

	smallChunk := 1 << 10  // 1 KB
	mediumChunk := 1 << 12 // 4 KB
	current := sources.TotalChunkSize
	largeChunk := 1 << 14 // 16 KB
	xlChunk := 1 << 15    // 32 KB
	xxlChunk := 1 << 16   // 64 KB
	xxxlChunk := 1 << 18  // 256 KB
	chunkSizes := []int{smallChunk, mediumChunk, current, largeChunk, xlChunk, xxlChunk, xxxlChunk}

	for _, chunkSize := range chunkSizes {
		b.Run(fmt.Sprintf("ChunkSize_%d", chunkSize), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(chunkSize))

			// Create a single chunk of the desired size.
			chunk := sampleData[:chunkSize]

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				ac.FindDetectorMatches([]byte(chunk)) // Match against the single chunk
			}
		})
	}
}

func generateRandomDataWithKeywords(size int, detectors []detectors.Detector) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	data := make([]byte, size)

	r := rand.New(rand.NewSource(42)) // Seed for reproducibility

	for i := range data {
		data[i] = charset[r.Intn(len(charset))]
	}

	totalKeywords := 0
	for _, d := range detectors {
		totalKeywords += len(d.Keywords())
	}

	// Target keyword density (keywords per character)
	// This ensures that the generated data has a reasonable number of keywords and is consistent
	// across different data sizes.
	keywordDensity := 0.01

	targetKeywords := int(float64(size) * keywordDensity)

	for i := 0; i < targetKeywords; i++ {
		detectorIndex := r.Intn(len(detectors))
		keywordIndex := r.Intn(len(detectors[detectorIndex].Keywords()))
		keyword := detectors[detectorIndex].Keywords()[keywordIndex]

		insertPosition := r.Intn(size - len(keyword))
		copy(data[insertPosition:], keyword)
	}

	return string(data)
}

func TestEngine_ShouldVerifyChunk(t *testing.T) {
	tests := []struct {
		name        string
		detector    detectors.Detector
		overrideKey config.DetectorID
		want        func(sourceVerify, detectorVerify bool) bool
	}{
		{
			name:        "detector override by exact version",
			detector:    &gitlab.Scanner{},
			overrideKey: config.DetectorID{ID: detectorspb.DetectorType_Gitlab, Version: 2},
			want:        func(sourceVerify, detectorVerify bool) bool { return detectorVerify },
		},
		{
			name:        "detector override by versionless config",
			detector:    &gitlab.Scanner{},
			overrideKey: config.DetectorID{ID: detectorspb.DetectorType_Gitlab, Version: 0},
			want:        func(sourceVerify, detectorVerify bool) bool { return detectorVerify },
		},
		{
			name:        "no detector override because of detector type mismatch",
			detector:    &gitlab.Scanner{},
			overrideKey: config.DetectorID{ID: detectorspb.DetectorType_NpmToken, Version: 2},
			want:        func(sourceVerify, detectorVerify bool) bool { return sourceVerify },
		},
		{
			name:        "no detector override because of detector version mismatch",
			detector:    &gitlab.Scanner{},
			overrideKey: config.DetectorID{ID: detectorspb.DetectorType_Gitlab, Version: 1},
			want:        func(sourceVerify, detectorVerify bool) bool { return sourceVerify },
		},
	}

	booleanChoices := [2]bool{true, false}

	engine := &Engine{verify: true}

	for _, tt := range tests {
		for _, sourceVerify := range booleanChoices {
			for _, detectorVerify := range booleanChoices {

				t.Run(fmt.Sprintf("%s (source verify = %v, detector verify = %v)", tt.name, sourceVerify, detectorVerify), func(t *testing.T) {
					overrides := map[config.DetectorID]bool{
						tt.overrideKey: detectorVerify,
					}

					want := tt.want(sourceVerify, detectorVerify)

					got := engine.shouldVerifyChunk(sourceVerify, tt.detector, overrides)

					assert.Equal(t, want, got)
				})
			}
		}
	}
}

func TestEngineInitializesCloudProviderDetectors(t *testing.T) {
	ctx := context.Background()
	conf := Config{
		Concurrency:   1,
		Detectors:     defaults.DefaultDetectors(),
		Verify:        false,
		SourceManager: sources.NewManager(),
		Dispatcher:    NewPrinterDispatcher(new(discardPrinter)),
	}

	e, err := NewEngine(ctx, &conf)
	assert.NoError(t, err)

	var count int
	for _, det := range e.detectors {
		if endpoints, ok := det.(interface{ Endpoints(...string) []string }); ok {
			id := config.GetDetectorID(det)
			if len(endpoints.Endpoints()) == 0 && det.Type() != detectorspb.DetectorType_ArtifactoryAccessToken && det.Type() != detectorspb.DetectorType_TableauPersonalAccessToken { // artifactory and tableau does not have any cloud endpoint
				t.Fatalf("detector %q Endpoints() is empty", id.String())
			}
			count++
		}
	}

	if count == 0 {
		t.Fatal("no detectors found implementing Endpoints(), did EndpointSetter change?")
	}
}

func TestEngineignoreLine(t *testing.T) {
	tests := []struct {
		name             string
		content          string
		expectedFindings int
	}{
		{
			name: "ignore at end of line",
			content: `
# tests/example_false_positive.py

def test_something():
    connection_string = "who-cares"

    # Ignoring this does not work
    assert connection_string == "postgres://master_user:master_password@hostname:1234/main"  # trufflehog:ignore`,
			expectedFindings: 0,
		},
		{
			name: "ignore not on secret line",
			content: `
# tests/example_false_positive.py

def test_something():
    connection_string = "who-cares"

    # Ignoring this does not work
	assert some_other_stuff == "blah" # trufflehog:ignore
    assert connection_string == "postgres://master_user:master_password@hostname:1234/main"`,
			expectedFindings: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			tmpFile, err := os.CreateTemp("", "test_creds")
			assert.NoError(t, err)
			defer os.Remove(tmpFile.Name())

			err = os.WriteFile(tmpFile.Name(), []byte(tt.content), os.ModeAppend)
			assert.NoError(t, err)

			const defaultOutputBufferSize = 64
			opts := []func(*sources.SourceManager){
				sources.WithSourceUnits(),
				sources.WithBufferedOutput(defaultOutputBufferSize),
			}

			sourceManager := sources.NewManager(opts...)

			conf := Config{
				Concurrency:   1,
				Decoders:      decoders.DefaultDecoders(),
				Detectors:     defaults.DefaultDetectors(),
				Verify:        false,
				SourceManager: sourceManager,
				Dispatcher:    NewPrinterDispatcher(new(discardPrinter)),
			}

			eng, err := NewEngine(ctx, &conf)
			assert.NoError(t, err)

			eng.Start(ctx)

			cfg := sources.FilesystemConfig{Paths: []string{tmpFile.Name()}}
			_, err = eng.ScanFileSystem(ctx, cfg)
			assert.NoError(t, err)

			assert.NoError(t, eng.Finish(ctx))
			assert.Equal(t, tt.expectedFindings, int(eng.GetMetrics().UnverifiedSecretsFound))
		})
	}
}

type passthroughDetector struct {
	detectorType detectorspb.DetectorType
	keywords     []string
	secret       string
}

func (p passthroughDetector) FromData(_ aCtx.Context, verify bool, data []byte) ([]detectors.Result, error) {
	raw := data
	if p.secret != "" {
		raw = []byte(p.secret)
	}
	return []detectors.Result{
		{
			Raw:      raw,
			Verified: verify,
		},
	}, nil
}

func (p passthroughDetector) Keywords() []string             { return p.keywords }
func (p passthroughDetector) Type() detectorspb.DetectorType { return p.detectorType }
func (p passthroughDetector) Description() string            { return "fake detector for testing" }

type passthroughDecoder struct{}

func (p passthroughDecoder) FromChunk(chunk *sources.Chunk) *decoders.DecodableChunk {
	return &decoders.DecodableChunk{
		Chunk:       chunk,
		DecoderType: detectorspb.DecoderType(-1),
	}
}

func (p passthroughDecoder) Type() detectorspb.DecoderType { return detectorspb.DecoderType(-1) }

func TestEngine_DetectChunk_UsesVerifyFlag(t *testing.T) {
	ctx := context.Background()

	// Arrange: Create a minimal engine.
	e := &Engine{
		results:           make(chan detectors.ResultWithMetadata, 1),
		verificationCache: verificationcache.New(nil, &verificationcache.InMemoryMetrics{}),
	}

	// Arrange: Create a detector match. We can't create one directly, so we have to use a minimal A-H core.
	ahcore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{passthroughDetector{keywords: []string{"keyword"}}})
	detectorMatches := ahcore.FindDetectorMatches([]byte("keyword"))
	require.Len(t, detectorMatches, 1)

	// Arrange: Create a chunk to detect.
	chunk := detectableChunk{
		chunk: sources.Chunk{
			Verify: true,
		},
		detector: detectorMatches[0],
		wgDoneFn: func() {},
	}

	// Act
	e.detectChunk(ctx, chunk)
	close(e.results)

	// Assert: Confirm that a result was generated and that it has the expected verify flag.
	select {
	case result := <-e.results:
		assert.True(t, result.Result.Verified)
	default:
		t.Errorf("expected a result but did not get one")
	}
}

func TestEngine_ScannerWorker_DetectableChunkHasCorrectVerifyFlag(t *testing.T) {
	ctx := context.Background()

	// Arrange: Create a minimal engine.
	detector := &passthroughDetector{keywords: []string{"keyword"}}
	e := &Engine{
		AhoCorasickCore:      ahocorasick.NewAhoCorasickCore([]detectors.Detector{detector}),
		decoders:             []decoders.Decoder{passthroughDecoder{}},
		detectableChunksChan: make(chan detectableChunk, 1),
		sourceManager:        sources.NewManager(),
		verify:               true,
	}

	// Arrange: Create a chunk to scan.
	chunk := sources.Chunk{
		Data:   []byte("keyword"),
		Verify: true,
	}

	// Arrange: Enqueue a chunk to be scanned.
	e.sourceManager.ScanChunk(&chunk)

	// Act
	go e.scannerWorker(ctx)

	// Assert: Confirm that a chunk was generated and that it has the expected verify flag.
	select {
	case chunk := <-e.detectableChunksChan:
		assert.True(t, chunk.chunk.Verify)
	case <-time.After(1 * time.Second):
		t.Errorf("expected a detectableChunk but did not get one")
	}
}

func TestEngine_VerificationOverlapWorker_DetectableChunkHasCorrectVerifyFlag(t *testing.T) {
	ctx := context.Background()

	t.Run("overlap", func(t *testing.T) {
		// Arrange: Create a minimal engine
		e := &Engine{
			detectableChunksChan:          make(chan detectableChunk, 2),
			results:                       make(chan detectors.ResultWithMetadata, 2),
			retainFalsePositives:          true,
			verificationOverlapChunksChan: make(chan verificationOverlapChunk, 2),
			verify:                        true,
		}

		// Arrange: Set up a fake detectableChunk processor so that any chunks (incorrectly) sent to
		// e.detectableChunksChan don't block the test.
		processedDetectableChunks := make(chan detectableChunk, 2)
		go func() {
			for chunk := range e.detectableChunksChan {
				chunk.wgDoneFn()
				processedDetectableChunks <- chunk
			}
		}()

		// Arrange: Create a chunk to "scan."
		chunk := sources.Chunk{
			Data:   []byte("keyword ;oahpow8heg;blaisd"),
			Verify: true,
		}

		// Arrange: Create overlapping detector matches. We can't create them directly, so we have to use a minimal A-H
		// core.
		ahcore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{
			passthroughDetector{detectorType: detectorspb.DetectorType(-1), keywords: []string{"keyw"}},
			passthroughDetector{detectorType: detectorspb.DetectorType(-2), keywords: []string{"keyword"}},
		})
		detectorMatches := ahcore.FindDetectorMatches(chunk.Data)
		require.Len(t, detectorMatches, 2)

		// Arrange: Enqueue a verification overlap chunk
		e.verificationOverlapChunksChan <- verificationOverlapChunk{
			chunk:                       chunk,
			detectors:                   detectorMatches,
			verificationOverlapWgDoneFn: func() { close(e.verificationOverlapChunksChan) },
		}

		// Act
		e.verificationOverlapWorker(ctx)
		close(e.results)
		close(e.detectableChunksChan)
		close(processedDetectableChunks)

		// Assert: Confirm that every generated result is unverified (because overlap detection precluded it).
		for result := range e.results {
			assert.False(t, result.Result.Verified)
		}

		// Assert: Confirm that every generated detectable chunk carries the original Verify flag.
		// CMR: There should be not be any of these chunks. However, due to what I believe is an unrelated bug, there
		// are. This test ensures that even in that erroneous case, their Verify flag is correct.
		for detectableChunk := range processedDetectableChunks {
			assert.True(t, detectableChunk.chunk.Verify)
		}
	})
	t.Run("no overlap", func(t *testing.T) {
		// Arrange: Create a minimal engine
		e := &Engine{
			detectableChunksChan:          make(chan detectableChunk, 2),
			retainFalsePositives:          true,
			verificationOverlapChunksChan: make(chan verificationOverlapChunk, 2),
			verify:                        true,
		}

		// Arrange: Set up a fake detectableChunk processor so that any chunks sent to e.detectableChunksChan don't
		// block the test.
		processedDetectableChunks := make(chan detectableChunk, 2)
		go func() {
			for chunk := range e.detectableChunksChan {
				chunk.wgDoneFn()
				processedDetectableChunks <- chunk
			}
		}()

		// Arrange: Create a chunk to "scan."
		chunk := sources.Chunk{
			Data:   []byte("keyword ;oahpow8heg;blaisd"),
			Verify: true,
		}

		// Arrange: Create non-overlapping detector matches. We can't create them directly, so we have to use a minimal
		// A-H core.
		ahcore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{
			passthroughDetector{detectorType: detectorspb.DetectorType(-1), keywords: []string{"keyw"}, secret: "oahpow"},
			passthroughDetector{detectorType: detectorspb.DetectorType(-2), keywords: []string{"keyword"}, secret: "blaisd"},
		})
		detectorMatches := ahcore.FindDetectorMatches(chunk.Data)
		require.Len(t, detectorMatches, 2)

		// Arrange: Enqueue a verification overlap chunk
		e.verificationOverlapChunksChan <- verificationOverlapChunk{
			chunk:                       chunk,
			detectors:                   detectorMatches,
			verificationOverlapWgDoneFn: func() { close(e.verificationOverlapChunksChan) },
		}

		// Act
		e.verificationOverlapWorker(ctx)
		close(e.detectableChunksChan)
		close(processedDetectableChunks)

		// Assert: Confirm that every generated detectable chunk carries the original Verify flag.
		for detectableChunk := range processedDetectableChunks {
			assert.True(t, detectableChunk.chunk.Verify)
		}
	})
}

func TestEngine_IterativeDecoding(t *testing.T) {
	t.Parallel()

	// base64(base64("my-secret-key-test-value"))
	const (
		doubleEncoded   = "YlhrdGMyVmpjbVYwTFd0bGVTMTBaWE4wTFhaaGJIVmw="
		detectorKeyword = "my-secret"
	)

	// "token: bXktc2VjcmV0LWtleS10ZXN0LXZhbHVl end" as UTF-16LE
	utf16ContainingBase64 := []byte{
		116, 0, 111, 0, 107, 0, 101, 0, 110, 0, 58, 0, 32, 0,
		98, 0, 88, 0, 107, 0, 116, 0, 99, 0, 50, 0, 86, 0, 106, 0,
		99, 0, 109, 0, 86, 0, 48, 0, 76, 0, 87, 0, 116, 0, 108, 0,
		101, 0, 83, 0, 49, 0, 48, 0, 90, 0, 88, 0, 78, 0, 48, 0,
		76, 0, 88, 0, 90, 0, 104, 0, 98, 0, 72, 0, 86, 0, 108, 0,
		32, 0, 101, 0, 110, 0, 100, 0,
	}

	tests := []struct {
		name        string
		input       []byte
		depth       int
		wantKeyword bool
	}{
		{
			name:        "double base64, depth=1, miss",
			input:       []byte("token: " + doubleEncoded),
			depth:       1,
			wantKeyword: false,
		},
		{
			name:        "double base64, depth=2, found",
			input:       []byte("token: " + doubleEncoded),
			depth:       2,
			wantKeyword: true,
		},
		{
			name:        "utf16+base64, depth=1, miss",
			input:       utf16ContainingBase64,
			depth:       1,
			wantKeyword: false,
		},
		{
			name:        "utf16+base64, depth=2, found",
			input:       utf16ContainingBase64,
			depth:       2,
			wantKeyword: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()

			detector := &passthroughDetector{
				keywords:     []string{detectorKeyword},
				detectorType: detectorspb.DetectorType(9999),
			}
			e := &Engine{
				AhoCorasickCore:      ahocorasick.NewAhoCorasickCore([]detectors.Detector{detector}),
				decoders:             decoders.DefaultDecoders(),
				detectableChunksChan: make(chan detectableChunk, 64),
				sourceManager:        sources.NewManager(),
				maxDecodeDepth:       tt.depth,
			}

			e.sourceManager.ScanChunk(&sources.Chunk{Data: tt.input})
			go e.scannerWorker(ctx)

			var found bool
			timeout := time.After(2 * time.Second)
		Loop:
			for {
				select {
				case dc := <-e.detectableChunksChan:
					dc.wgDoneFn()
					found = true
					for {
						select {
						case dc2 := <-e.detectableChunksChan:
							dc2.wgDoneFn()
						case <-time.After(200 * time.Millisecond):
							break Loop
						}
					}
				case <-timeout:
					break Loop
				}
			}

			if tt.wantKeyword {
				assert.True(t, found, "expected detector match")
			} else {
				assert.False(t, found, "unexpected detector match")
			}
		})
	}
}
