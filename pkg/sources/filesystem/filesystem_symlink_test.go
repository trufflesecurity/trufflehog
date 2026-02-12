package filesystem

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sourcestest"
)

func probeSymlinkSupport(t *testing.T, baseDir string) {
	probe := filepath.Join(baseDir, "symlink-probe")
	if err := os.Symlink("x", probe); err != nil {
		t.Skip("symlinks not supported")
	}
	_ = os.Remove(probe)
}

func TestScanDir_VisitedPath_PreventInfiniteRecursion(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()
	baseDir, cleanup, err := createTempDir("")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	// Skip if symlinks unsupported
	probeSymlinkSupport(t, baseDir)

	dirA := filepath.Join(baseDir, "A")
	dirB := filepath.Join(baseDir, "B")
	err = os.Mkdir(dirA, 0755)
	if err != nil {
		t.Fatalf("Unable to create directory A %v", err)
	}
	err = os.Mkdir(dirB, 0755)
	if err != nil {
		t.Fatalf("Unable to create directory B %v", err)
	}

	// We create
	// A/linkToB -> /B
	// B/linkToA -> /A
	err = os.Symlink(dirB, filepath.Join(dirA, "linkToB"))
	if err != nil {
		t.Fatalf("Unable to create symlink %v", err)
	}
	err = os.Symlink(dirA, filepath.Join(dirB, "linkToA"))
	if err != nil {
		t.Fatalf("Unable to create symlink %v", err)
	}

	src := &Source{
		followSymlinks:      true,
		concurrency:         1,
		maxSymlinkDepth:     20,
		visitedSymlinkPaths: make(map[string]struct{}),
	}
	err = src.scanDir(ctx, filepath.Join(dirA, "linkToB"), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestChunks_DirectorySymlinkLoop(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()
	baseDir, cleanup, err := createTempDir("")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	probeSymlinkSupport(t, baseDir)

	// We Create
	// /A->/B
	// /B->/A
	err = os.Symlink(filepath.Join(baseDir, "B"), filepath.Join(baseDir, "A"))
	if err != nil {
		t.Fatalf("Unable to create symlink %v", err)
	}
	err = os.Symlink(filepath.Join(baseDir, "A"), filepath.Join(baseDir, "B"))
	if err != nil {
		t.Fatalf("Unable to create symlink %v", err)
	}

	src := &Source{
		followSymlinks:  true,
		maxSymlinkDepth: 20,
		concurrency:     1,
		paths:           []string{filepath.Join(baseDir, "B")},
	}

	chunks := make(chan *sources.Chunk, 10)
	// Run the scan
	go func() {
		err := src.Chunks(ctx, chunks)
		require.NoError(t, err)
		close(chunks)
	}()
	var chunkCount int
	for range chunks {
		chunkCount++
	}
	// Assert no chunks were emitted due to the infinite symlink loop
	require.Equal(t, 0, chunkCount, "No chunks should be processed due to infinite symlink loop")
}

func TestChunkUnit_DirectorySymlinkLoop(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()
	baseDir, cleanup, err := createTempDir("")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	probeSymlinkSupport(t, baseDir)

	// We Create
	// /A->/B
	// /B->/A
	err = os.Symlink(filepath.Join(baseDir, "B"), filepath.Join(baseDir, "A"))
	if err != nil {
		t.Fatalf("Unable to create symlink %v", err)
	}
	err = os.Symlink(filepath.Join(baseDir, "A"), filepath.Join(baseDir, "B"))
	if err != nil {
		t.Fatalf("Unable to create symlink %v", err)
	}

	conn, err := anypb.New(&sourcespb.Filesystem{
		MaxSymlinkDepth: 20,
	})
	assert.NoError(t, err)

	// Initialize the source.
	s := Source{}
	err = s.Init(ctx, "test chunk unit", 0, 0, true, conn, 1)
	assert.NoError(t, err)

	reporter := sourcestest.TestReporter{}
	err = s.ChunkUnit(ctx, sources.CommonSourceUnit{
		ID: filepath.Join(baseDir, "B"),
	}, &reporter)
	assert.NoError(t, err)
	// Assert no chunks were emitted due to the infinite symlink loop
	assert.Equal(t, 0, len(reporter.Chunks))
}

func TestChunks_FileSymlinkLoop(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()
	baseDir, cleanup, err := createTempDir("")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	probeSymlinkSupport(t, baseDir)

	// We Create
	// /fileA->/fileB
	// /fileB->/fileA
	fileA := filepath.Join(baseDir, "fileA.txt")
	fileB := filepath.Join(baseDir, "fileB.txt")
	err = os.Symlink(fileA, fileB)
	if err != nil {
		t.Fatalf("Unable to create symlink %v", err)
	}
	err = os.Symlink(fileB, fileA)
	if err != nil {
		t.Fatalf("Unable to create symlink %v", err)
	}

	src := &Source{
		followSymlinks:  true,
		maxSymlinkDepth: 20,
		concurrency:     1,
		paths:           []string{fileA},
	}

	chunks := make(chan *sources.Chunk, 10)
	// Run the scan
	go func() {
		err := src.Chunks(ctx, chunks)
		require.NoError(t, err)
		close(chunks)
	}()
	var chunkCount int
	for range chunks {
		chunkCount++
	}
	// Assert no chunks were emitted due to the infinite symlink loop
	require.Equal(t, 0, chunkCount, "No chunks should be processed due to infinite symlink loop")
}

func TestChunkUnit_FileSymlinkLoop(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	baseDir, cleanup, err := createTempDir("")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	// Probe symlink support
	probeSymlinkSupport(t, baseDir)

	// Create two files that are symlinks to each other
	fileA := filepath.Join(baseDir, "fileA.txt")
	fileB := filepath.Join(baseDir, "fileB.txt")

	if err := os.Symlink(fileB, fileA); err != nil {
		t.Fatalf("Unable to create symlink %v", err)
	}
	if err := os.Symlink(fileA, fileB); err != nil {
		t.Fatalf("Unable to create symlink %v", err)
	}

	conn, err := anypb.New(&sourcespb.Filesystem{
		MaxSymlinkDepth: 20,
	})
	require.NoError(t, err)

	s := Source{}
	err = s.Init(ctx, "test chunk unit", 0, 0, true, conn, 1)
	require.NoError(t, err)

	reporter := sourcestest.TestReporter{}
	err = s.ChunkUnit(ctx, sources.CommonSourceUnit{
		ID: fileA,
	}, &reporter)
	require.NoError(t, err)

	// Assert no chunks were emitted due to the infinite symlink loop
	assert.Equal(t, 0, len(reporter.Chunks), "No chunks should be processed due to infinite symlink loop")
}

func TestChunks_ValidDirectorySymlink(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Create a temporary base directory
	baseDir, cleanup, err := createTempDir("")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	// Probe symlink support
	probeSymlinkSupport(t, baseDir)

	// Create a real file
	dirA := filepath.Join(baseDir, "A")
	err = os.Mkdir(dirA, 0755)
	if err != nil {
		t.Fatalf("Unable to create directory A %v", err)
	}
	dirB := filepath.Join(baseDir, "B")
	err = os.Mkdir(dirB, 0755)
	if err != nil {
		t.Fatalf("Unable to create directory B %v", err)
	}

	data := "Hello world!"
	file, cleanupFile, err := createTempFile(dirA, data)
	assert.NoError(t, err)
	defer cleanupFile()

	// we create
	// /B/link.txt->/A/trufflehogtest*
	linkFile := filepath.Join(dirB, "link.txt")
	if err := os.Symlink(file.Name(), linkFile); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	src := &Source{
		followSymlinks:  true,
		concurrency:     1,
		paths:           []string{dirB},
		maxSymlinkDepth: 20,
	}

	chunksCh := make(chan *sources.Chunk, 1)
	go func() {
		defer close(chunksCh)
		err = src.Chunks(ctx, chunksCh)
		require.NoError(t, err)
	}()
	if err != nil {
		t.Fatalf("unexpected error scanning symlink: %v", err)
	}

	for chunk := range chunksCh {
		if string(chunk.Data) != data {
			t.Fatalf("expected chunk.Data: %v to be equal to %v", string(chunk.Data), data)
		}
	}
}

func TestChunkUnit_ValidDirectorySymlink(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Create a temporary base directory
	baseDir, cleanup, err := createTempDir("")
	require.NoError(t, err)
	defer cleanup()

	// Probe symlink support
	probeSymlinkSupport(t, baseDir)

	// Create directories
	dirA := filepath.Join(baseDir, "A")
	dirB := filepath.Join(baseDir, "B")
	require.NoError(t, os.Mkdir(dirA, 0755))
	require.NoError(t, os.Mkdir(dirB, 0755))

	// Create a file in dirA
	data := "Hello world!"
	file, cleanupFile, err := createTempFile(dirA, data)
	require.NoError(t, err)
	defer cleanupFile()

	// Create symlink: /B/link.txt -> /A/trufflehogtest*
	linkFile := filepath.Join(dirB, "link.txt")
	require.NoError(t, os.Symlink(file.Name(), linkFile))

	// Prepare Source
	conn, err := anypb.New(&sourcespb.Filesystem{
		MaxSymlinkDepth: 20,
	})
	require.NoError(t, err)

	src := Source{}
	require.NoError(t, src.Init(ctx, "test chunk unit", 0, 0, true, conn, 1))

	reporter := sourcestest.TestReporter{}
	err = src.ChunkUnit(ctx, sources.CommonSourceUnit{
		ID: dirB,
	}, &reporter)
	require.NoError(t, err)

	// Assert exactly 1 chunk is scanned and data matches
	require.Len(t, reporter.Chunks, 1, "Expected exactly 1 chunk from symlinked file")
	require.Equal(t, data, string(reporter.Chunks[0].Data))
}

func TestChunks_ValidFileSymlink(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Create a temporary base directory
	baseDir, cleanup, err := createTempDir("")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	// Probe symlink support
	probeSymlinkSupport(t, baseDir)

	// Create a real file
	dirA := filepath.Join(baseDir, "A")
	err = os.Mkdir(dirA, 0755)
	if err != nil {
		t.Fatalf("Unable to create directory A %v", err)
	}
	dirB := filepath.Join(baseDir, "B")
	err = os.Mkdir(dirB, 0755)
	if err != nil {
		t.Fatalf("Unable to create directory B %v", err)
	}

	data := "Hello world!"
	file, cleanupFile, err := createTempFile(dirA, data)
	assert.NoError(t, err)
	defer cleanupFile()

	// we create
	// /B/link.txt->/A/trufflehogtest*
	linkFile := filepath.Join(dirB, "link.txt")
	if err := os.Symlink(file.Name(), linkFile); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	src := &Source{
		followSymlinks:  true,
		concurrency:     1,
		maxSymlinkDepth: 20,
		paths:           []string{linkFile},
	}

	chunksCh := make(chan *sources.Chunk, 1)

	go func() {
		defer close(chunksCh)
		err = src.Chunks(ctx, chunksCh)
		if err != nil {
			t.Errorf("src.scanFile() error=%v", err)
		}
	}()

	if err != nil {
		t.Fatalf("unexpected error scanning symlink: %v", err)
	}

	for chunk := range chunksCh {
		if string(chunk.Data) != data {
			t.Fatalf("expected chunk.Data: %v to be equal to %v", string(chunk.Data), data)
		}
	}
}

func TestChunkUnit_ValidFileSymlink(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Create a temporary base directory
	baseDir, cleanup, err := createTempDir("")
	require.NoError(t, err)
	defer cleanup()

	probeSymlinkSupport(t, baseDir)

	dirA := filepath.Join(baseDir, "A")
	dirB := filepath.Join(baseDir, "B")
	require.NoError(t, os.Mkdir(dirA, 0755))
	require.NoError(t, os.Mkdir(dirB, 0755))

	data := "Hello world!"
	file, cleanupFile, err := createTempFile(dirA, data)
	require.NoError(t, err)
	defer cleanupFile()

	// Create symlink: /B/link.txt -> /A/trufflehogtest*
	linkFile := filepath.Join(dirB, "link.txt")
	require.NoError(t, os.Symlink(file.Name(), linkFile))

	conn, err := anypb.New(&sourcespb.Filesystem{
		MaxSymlinkDepth: 20,
	})
	require.NoError(t, err)

	src := Source{}
	require.NoError(t, src.Init(ctx, "test chunk unit", 0, 0, true, conn, 1))

	reporter := sourcestest.TestReporter{}
	err = src.ChunkUnit(ctx, sources.CommonSourceUnit{
		ID: linkFile,
	}, &reporter)
	require.NoError(t, err)

	// Assert exactly 1 chunk scanned and data matches
	require.Len(t, reporter.Chunks, 1, "Expected exactly 1 chunk from symlinked file")
	require.Equal(t, data, string(reporter.Chunks[0].Data))
}

func TestResolveSymlink_NoError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()
	baseDir, cleanup, err := createTempDir("")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	probeSymlinkSupport(t, baseDir)

	dirD := filepath.Join(baseDir, "D")
	err = os.Mkdir(dirD, 0755)
	if err != nil {
		t.Fatalf("Unable to create directory D %v", err)
	}

	err = os.Symlink(filepath.Join(baseDir, "B"), filepath.Join(baseDir, "A"))
	if err != nil {
		t.Fatalf("Unable to create symlink %v", err)
	}
	err = os.Symlink(filepath.Join(baseDir, "C"), filepath.Join(baseDir, "B"))
	if err != nil {
		t.Fatalf("Unable to create symlink %v", err)
	}
	err = os.Symlink(filepath.Join(baseDir, "D"), filepath.Join(baseDir, "C"))
	if err != nil {
		t.Fatalf("Unable to create symlink %v", err)
	}

	src := &Source{
		followSymlinks:  true,
		concurrency:     1,
		maxSymlinkDepth: 5,
	}
	var path string
	_, path, err = src.resolveSymLink(ctx, filepath.Join(baseDir, "A"))
	require.Nil(t, err)
	require.Equal(t, dirD, path)
}
func TestResolveSymlink_MaxDepthExceeded(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()
	baseDir, cleanup, err := createTempDir("")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	probeSymlinkSupport(t, baseDir)

	dirB := filepath.Join(baseDir, "D")
	err = os.Mkdir(dirB, 0755)
	if err != nil {
		t.Fatalf("Unable to create directory D %v", err)
	}

	err = os.Symlink(filepath.Join(baseDir, "B"), filepath.Join(baseDir, "A"))
	if err != nil {
		t.Fatalf("Unable to create symlink %v", err)
	}
	err = os.Symlink(filepath.Join(baseDir, "C"), filepath.Join(baseDir, "B"))
	if err != nil {
		t.Fatalf("Unable to create symlink %v", err)
	}
	err = os.Symlink(filepath.Join(baseDir, "D"), filepath.Join(baseDir, "C"))
	if err != nil {
		t.Fatalf("Unable to create symlink %v", err)
	}

	src := &Source{
		followSymlinks:  true,
		concurrency:     1,
		maxSymlinkDepth: 2,
	}
	_, _, err = src.resolveSymLink(ctx, filepath.Join(baseDir, "A"))
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Unable to resolve symlink")
	require.Contains(t, err.Error(), "for the specified depth 2")
}

func TestResolveSymlink_FileTarget(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	baseDir, cleanup, err := createTempDir("")
	require.NoError(t, err)
	defer cleanup()

	probeSymlinkSupport(t, baseDir)
	// Create a file
	filePath := filepath.Join(baseDir, "file.txt")
	err = os.WriteFile(filePath, []byte("data"), 0644)
	require.NoError(t, err)

	// Create a symlink pointing to the file
	symlinkPath := filepath.Join(baseDir, "link.txt")
	err = os.Symlink(filePath, symlinkPath)
	require.NoError(t, err)

	src := &Source{
		followSymlinks:  true,
		maxSymlinkDepth: 5,
	}

	info, resolved, err := src.resolveSymLink(ctx, symlinkPath)
	require.NoError(t, err)
	require.False(t, info.IsDir())
	require.Equal(t, filePath, resolved)
}

func TestResolveSymlink_SelfLoop(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	baseDir, cleanup, err := createTempDir("")
	require.NoError(t, err)
	defer cleanup()

	probeSymlinkSupport(t, baseDir)

	symlinkPath := filepath.Join(baseDir, "loop.txt")
	err = os.Symlink(symlinkPath, symlinkPath)
	require.NoError(t, err)

	src := &Source{
		followSymlinks:  true,
		maxSymlinkDepth: 5,
	}

	_, _, err = src.resolveSymLink(ctx, symlinkPath)
	require.Error(t, err)
	require.Contains(t, err.Error(), "Unable to resolve symlink")
}

func TestResolveSymlink_BrokenSymlink(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	baseDir, cleanup, err := createTempDir("")
	require.NoError(t, err)
	defer cleanup()

	probeSymlinkSupport(t, baseDir)

	symlinkPath := filepath.Join(baseDir, "broken")
	err = os.Symlink(filepath.Join(baseDir, "nonexistent.txt"), symlinkPath)
	require.NoError(t, err)

	src := &Source{
		followSymlinks:  true,
		maxSymlinkDepth: 5,
	}

	_, _, err = src.resolveSymLink(ctx, symlinkPath)
	require.Error(t, err)
	require.Contains(t, err.Error(), "Error in retrieving info")
}

func TestResolveSymlink_TwoFileLoop(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	baseDir, cleanup, err := createTempDir("")
	require.NoError(t, err)
	defer cleanup()

	probeSymlinkSupport(t, baseDir)

	fileA := filepath.Join(baseDir, "fileA.txt")
	fileB := filepath.Join(baseDir, "fileB.txt")

	// A -> B, B -> A
	require.NoError(t, os.Symlink(fileB, fileA))
	require.NoError(t, os.Symlink(fileA, fileB))

	src := &Source{
		followSymlinks:  true,
		maxSymlinkDepth: 5,
	}

	_, _, err = src.resolveSymLink(ctx, fileA)
	require.Error(t, err)
	require.Contains(t, err.Error(), "Unable to resolve symlink")
}
