package filesystem

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/anypb"

	trContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sourcestest"
)

func TestSource_Scan(t *testing.T) {
	ctx, cancel := trContext.WithTimeout(trContext.Background(), time.Second*3)
	defer cancel()

	type init struct {
		name       string
		verify     bool
		connection *sourcespb.Filesystem
	}
	tests := []struct {
		name               string
		init               init
		wantSourceMetadata *source_metadatapb.MetaData
		wantErr            bool
	}{
		{
			name: "get a chunk",
			init: init{
				name: "this repo",
				connection: &sourcespb.Filesystem{
					Paths: []string{"."},
				},
				verify: true,
			},
			wantSourceMetadata: &source_metadatapb.MetaData{
				Data: &source_metadatapb.MetaData_Filesystem{
					Filesystem: &source_metadatapb.Filesystem{
						File: "filesystem.go",
						Line: 1, // First chunk starts at line 1
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Source{}

			conn, err := anypb.New(tt.init.connection)
			if err != nil {
				t.Fatal(err)
			}

			err = s.Init(ctx, tt.init.name, 0, 0, tt.init.verify, conn, 5)
			if (err != nil) != tt.wantErr {
				t.Errorf("Source.Init() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			chunksCh := make(chan *sources.Chunk, 1)
			// TODO: this is kind of bad, if it errors right away we don't see it as a test failure.
			// Debugging this usually requires setting a breakpoint on L78 and running test w/ debug.
			go func() {
				defer close(chunksCh)
				err = s.Chunks(ctx, chunksCh)
				if (err != nil) != tt.wantErr {
					t.Errorf("Source.Chunks() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
			}()
			var counter int
			for chunk := range chunksCh {
				if chunk.SourceMetadata.GetFilesystem().GetFile() == "filesystem.go" {
					counter++
					if diff := cmp.Diff(tt.wantSourceMetadata, chunk.SourceMetadata, protocmp.Transform()); diff != "" && counter == 1 { // First chunk should start at line 1
						t.Errorf("Source.Chunks() %s metadata mismatch (-want +got):\n%s", tt.name, diff)
					}
				}
			}
			assert.Equal(t, 2, counter)
		})
	}
}

func TestScanFile(t *testing.T) {
	chunkSize := sources.DefaultChunkSize
	secretPart1 := "SECRET"
	secretPart2 := "SPLIT"
	// Split the secret into two parts and pad the rest of the chunk with A's.
	data := strings.Repeat("A", chunkSize-len(secretPart1)) + secretPart1 + secretPart2 + strings.Repeat("A", chunkSize-len(secretPart2))

	tmpfile, cleanup, err := createTempFile("", data)
	assert.Nil(t, err)
	defer cleanup()

	source := &Source{}
	chunksChan := make(chan *sources.Chunk, 2)

	ctx := trContext.WithLogger(trContext.Background(), logr.Discard())
	go func() {
		defer close(chunksChan)
		err = source.scanFile(ctx, chunksChan, tmpfile.Name())
		assert.Nil(t, err)
	}()

	// Read from the channel and validate the secrets.
	foundSecret := ""
	for chunkCh := range chunksChan {
		foundSecret += string(chunkCh.Data)
	}

	assert.Contains(t, foundSecret, secretPart1+secretPart2)
}

func TestScanBinaryFile(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "example.bin")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())

	// binary data that decodes to "TuffleHog"
	fileContents := []byte{0x54, 0x75, 0x66, 0x66, 0x6C, 0x65, 0x48, 0x6F, 0x67}
	_, err = tmpfile.Write(fileContents)
	require.NoError(t, err)
	require.NoError(t, tmpfile.Close())

	source := &Source{}
	chunksChan := make(chan *sources.Chunk, 2)
	errChan := make(chan error, 1)

	ctx := trContext.WithLogger(trContext.Background(), logr.Discard())

	go func() {
		defer close(chunksChan)
		errChan <- source.scanFile(ctx, chunksChan, tmpfile.Name())
	}()

	err = <-errChan
	require.NoError(t, err)

	var data string
	for chunk := range chunksChan {
		require.NotNil(t, chunk)
		data += string(chunk.Data)
	}

	assert.Contains(t, data, "TuffleHog")
}

func TestEnumerate(t *testing.T) {
	// TODO: refactor to allow a virtual filesystem.
	t.Parallel()
	ctx := trContext.Background()

	// Setup the connection to test enumeration.
	dir, err := os.MkdirTemp("", "trufflehog-test-enumerate")
	assert.NoError(t, err)
	defer os.RemoveAll(dir)

	units := []string{
		"/one", "/two", "/three",
		"/path/to/dir/", "/path/to/another/dir/",
	}
	// Prefix the units with the tempdir and create files on disk.
	for i, unit := range units {
		fullPath := filepath.Join(dir, unit)
		units[i] = fullPath
		if i < 3 {
			f, err := os.Create(fullPath)
			assert.NoError(t, err)
			f.Close()
		} else {
			assert.NoError(t, os.MkdirAll(fullPath, 0755))
			// Create a file in the directory for enumeration to find.
			f, err := os.CreateTemp(fullPath, "file")
			assert.NoError(t, err)
			units[i] = f.Name()
			f.Close()
		}
	}
	conn, err := anypb.New(&sourcespb.Filesystem{
		Paths:       units[0:3],
		Directories: units[3:],
	})
	assert.NoError(t, err)

	// Initialize the source.
	s := Source{}
	err = s.Init(ctx, "test enumerate", 0, 0, true, conn, 1)
	assert.NoError(t, err)

	reporter := sourcestest.TestReporter{}
	err = s.Enumerate(ctx, &reporter)
	assert.NoError(t, err)

	assert.Equal(t, len(units), len(reporter.Units))
	assert.Equal(t, 0, len(reporter.UnitErrs))
	for _, unit := range reporter.Units {
		path, _ := unit.SourceUnitID()
		assert.Contains(t, units, path)
	}
	for _, unit := range units {
		assert.Contains(t, reporter.Units, sources.CommonSourceUnit{ID: unit})
	}
}

func TestChunkUnit(t *testing.T) {
	t.Parallel()
	ctx := trContext.Background()

	// Setup test file to chunk.
	fileContents := "TestChunkUnit"
	tmpfile, cleanup, err := createTempFile("", fileContents)
	assert.NoError(t, err)
	defer cleanup()

	tmpdir, cleanup, err := createTempDir("", "foo", "bar", "baz")
	assert.NoError(t, err)
	defer cleanup()

	conn, err := anypb.New(&sourcespb.Filesystem{})
	assert.NoError(t, err)

	// Initialize the source.
	s := Source{}
	err = s.Init(ctx, "test chunk unit", 0, 0, true, conn, 1)
	assert.NoError(t, err)

	// Happy path single file.
	reporter := sourcestest.TestReporter{}
	err = s.ChunkUnit(ctx, sources.CommonSourceUnit{
		ID: tmpfile.Name(),
	}, &reporter)
	assert.NoError(t, err)

	// Happy path directory.
	err = s.ChunkUnit(ctx, sources.CommonSourceUnit{
		ID: tmpdir,
	}, &reporter)
	assert.NoError(t, err)

	// Error path.
	err = s.ChunkUnit(ctx, sources.CommonSourceUnit{
		ID: "/file/not/found",
	}, &reporter)
	assert.NoError(t, err)

	assert.Equal(t, 4, len(reporter.Chunks))
	assert.Equal(t, 1, len(reporter.ChunkErrs))
	dataFound := make(map[string]struct{}, 4)
	for _, chunk := range reporter.Chunks {
		dataFound[string(chunk.Data)] = struct{}{}
	}
	assert.Contains(t, dataFound, fileContents)
	assert.Contains(t, dataFound, "foo")
	assert.Contains(t, dataFound, "bar")
	assert.Contains(t, dataFound, "baz")
}

func TestEnumerateReporterErr(t *testing.T) {
	t.Parallel()
	ctx := trContext.Background()

	// Setup the connection to test enumeration.
	units := []string{
		"/one", "/two", "/three",
		"/path/to/dir/", "/path/to/another/dir/",
	}
	conn, err := anypb.New(&sourcespb.Filesystem{
		Paths:       units[0:3],
		Directories: units[3:],
	})
	assert.NoError(t, err)

	// Initialize the source.
	s := Source{}
	err = s.Init(ctx, "test enumerate", 0, 0, true, conn, 1)
	assert.NoError(t, err)

	// Enumerate should always return an error if the reporter returns an
	// error.
	reporter := sourcestest.ErrReporter{}
	err = s.Enumerate(ctx, &reporter)
	assert.Error(t, err)
}

func TestChunkUnitReporterErr(t *testing.T) {
	t.Parallel()
	ctx := trContext.Background()

	// Setup test file to chunk.
	tmpfile, err := os.CreateTemp("", "example.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	fileContents := []byte("TestChunkUnit")
	_, err = tmpfile.Write(fileContents)
	assert.NoError(t, err)
	assert.NoError(t, tmpfile.Close())

	conn, err := anypb.New(&sourcespb.Filesystem{})
	assert.NoError(t, err)

	// Initialize the source.
	s := Source{}
	err = s.Init(ctx, "test chunk unit", 0, 0, true, conn, 1)
	assert.NoError(t, err)

	// Happy path. ChunkUnit should always return an error if the reporter
	// returns an error.
	reporter := sourcestest.ErrReporter{}
	err = s.ChunkUnit(ctx, sources.CommonSourceUnit{
		ID: tmpfile.Name(),
	}, &reporter)
	assert.Error(t, err)

	// Error path. ChunkUnit should always return an error if the reporter
	// returns an error.
	err = s.ChunkUnit(ctx, sources.CommonSourceUnit{
		ID: "/file/not/found",
	}, &reporter)
	assert.Error(t, err)
}

func TestSkipDir(t *testing.T) {
	t.Parallel()
	ctx := trContext.Background()

	// create a temp directory with files
	ignoreDir, cleanupDir, err := createTempDir("", "ignore1", "ignore2", "ignore3")
	require.NoError(t, err)
	defer cleanupDir()

	// create an ExcludePathsFile that contains the ignoreDir path
	// In windows path contains \ so we escape it by replacing it with \\ in ignoreDir
	excludeFile, cleanupFile, err := createTempFile("", strings.ReplaceAll(ignoreDir, `\`, `\\`)+"\n")
	require.NoError(t, err)
	defer cleanupFile()

	conn, err := anypb.New(&sourcespb.Filesystem{
		ExcludePathsFile: excludeFile.Name(),
	})
	require.NoError(t, err)

	// initialize the source.
	s := Source{}
	err = s.Init(ctx, "exclude directory", 0, 0, true, conn, 1)
	require.NoError(t, err)

	reporter := sourcestest.TestReporter{}
	err = s.ChunkUnit(ctx, sources.CommonSourceUnit{
		ID: ignoreDir,
	}, &reporter)
	require.NoError(t, err)

	require.Equal(t, 0, len(reporter.Chunks), "Expected no chunks from excluded directory")
	require.Equal(t, 0, len(reporter.ChunkErrs), "Expected no errors for excluded directory")
}

func TestScanSubDirFile(t *testing.T) {
	t.Parallel()
	ctx := trContext.Background()

	// Use a fixed directory for the test
	testDir := filepath.Join(os.TempDir(), "trufflehog-test")
	err := os.MkdirAll(testDir, 0755)
	require.NoError(t, err)
	defer os.RemoveAll(testDir)

	// Create a subdirectory and file
	childDir := filepath.Join(testDir, "child")
	err = os.MkdirAll(childDir, 0755)
	require.NoError(t, err)

	filePath := filepath.Join(childDir, "testfile.txt")
	err = os.WriteFile(filePath, []byte("should scan this file"), 0644)
	require.NoError(t, err)

	// Create an IncludePathsFile with the absolute path of the file
	includeFilePath := filepath.Join(testDir, "include.txt")
	err = os.WriteFile(includeFilePath, []byte(strings.ReplaceAll(filePath, `\`, `\\`)+"\n"), 0644)
	require.NoError(t, err)

	conn, err := anypb.New(&sourcespb.Filesystem{
		IncludePathsFile: includeFilePath,
	})
	require.NoError(t, err)

	// Initialize the source
	s := Source{}
	err = s.Init(ctx, "include sub directory file", 0, 0, true, conn, 1)
	require.NoError(t, err)

	reporter := sourcestest.TestReporter{}
	err = s.ChunkUnit(ctx, sources.CommonSourceUnit{
		ID: testDir,
	}, &reporter)
	require.NoError(t, err)
	require.Equal(t, 1, len(reporter.Chunks), "Expected chunks from included file")
	require.Equal(t, 0, len(reporter.ChunkErrs), "Expected no errors")
}

func TestSkipBinaries(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "trufflehog_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create a binary file (executable)
	binaryFile := filepath.Join(tempDir, "test.exe")
	err = os.WriteFile(binaryFile, []byte{0x4D, 0x5A, 0x90, 0x00}, 0644)
	require.NoError(t, err)

	// Create a text file
	textFile := filepath.Join(tempDir, "test.txt")
	err = os.WriteFile(textFile, []byte("This is a text file"), 0644)
	require.NoError(t, err)

	// Test with skipBinaries = true
	source := &Source{
		paths:        []string{textFile, binaryFile}, // Test individual files
		skipBinaries: true,
		log:          logr.Discard(),
	}

	chunks := make(chan *sources.Chunk, 10)
	ctx := trContext.Background()

	// Run the scan
	go func() {
		err := source.Chunks(ctx, chunks)
		require.NoError(t, err)
		close(chunks)
	}()

	// Collect chunks
	var chunkCount int
	var processedFiles []string
	for chunk := range chunks {
		chunkCount++
		metadata := chunk.SourceMetadata.GetFilesystem()
		require.NotNil(t, metadata)
		processedFiles = append(processedFiles, metadata.File)
	}

	// Should have exactly one chunk from the text file
	require.Equal(t, 1, chunkCount, "Should have processed exactly one text file")
	require.Contains(t, processedFiles, textFile, "Should have processed the text file")
	require.NotContains(t, processedFiles, binaryFile, "Binary file should be skipped")
}

func TestResumptionInfoDoesNotGrowWithSubdirectories(t *testing.T) {
	ctx := trContext.AddLogger(t.Context())

	// Create a deeply nested directory structure with files at each level.
	// Structure: root/dir0/dir1/dir2/.../dir9, each containing a file.
	rootDir, err := os.MkdirTemp("", "trufflehog-resumption-test")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(rootDir) })

	const numSubdirs = 10
	currentDir := rootDir
	for i := 0; i < numSubdirs; i++ {
		// Create a file in the current directory
		filePath := filepath.Join(currentDir, fmt.Sprintf("file%d.txt", i))
		err := os.WriteFile(filePath, []byte(fmt.Sprintf("content %d", i)), 0644)
		require.NoError(t, err)

		// Create the next subdirectory
		subDir := filepath.Join(currentDir, fmt.Sprintf("subdir%d", i))
		err = os.Mkdir(subDir, 0755)
		require.NoError(t, err)
		currentDir = subDir
	}
	// Create a file in the deepest directory
	err = os.WriteFile(filepath.Join(currentDir, "deepest.txt"), []byte("deepest"), 0644)
	require.NoError(t, err)

	conn, err := anypb.New(&sourcespb.Filesystem{MaxSymlinkDepth: 0})
	require.NoError(t, err)

	// Initialize the source.
	s := Source{}
	err = s.Init(ctx, "test resumption growth", 0, 0, true, conn, 1)
	require.NoError(t, err)

	// Track the maximum size of EncodedResumeInfo during the scan.
	var maxResumeInfoSize int
	var mu sync.Mutex

	// We need to periodically check the resume info size during scanning.
	// Run ChunkUnit in a goroutine and poll the progress.
	done := make(chan struct{})
	go func() {
		defer close(done)
		reporter := sourcestest.TestReporter{}
		err := s.ChunkUnit(ctx, sources.CommonSourceUnit{
			ID: rootDir,
		}, &reporter)
		require.NoError(t, err)
	}()

	// Poll the resume info size while scanning is in progress.
	ticker := time.NewTicker(1 * time.Millisecond)
	defer ticker.Stop()

polling:
	for {
		select {
		case <-done:
			break polling
		case <-ticker.C:
			progress := s.GetProgress()
			mu.Lock()
			if len(progress.EncodedResumeInfo) > maxResumeInfoSize {
				maxResumeInfoSize = len(progress.EncodedResumeInfo)
			}
			mu.Unlock()
		}
	}

	// After scan completes, check the final state.
	finalProgress := s.GetProgress()
	t.Logf("Final EncodedResumeInfo length: %d", len(finalProgress.EncodedResumeInfo))
	t.Logf("Max EncodedResumeInfo length during scan: %d", maxResumeInfoSize)

	// Parse the resume info to count entries if it's not empty.
	if maxResumeInfoSize > 0 {
		var resumeMap map[string]string
		err := json.Unmarshal([]byte(finalProgress.EncodedResumeInfo), &resumeMap)
		if err == nil {
			t.Logf("Final resume info entries: %d", len(resumeMap))
		}
	}

	// The key assertion: resumption info should NOT grow proportionally with
	// the number of subdirectories. During the scan, it should only track the
	// current position, not accumulate entries for every directory visited.
	//
	// With proper implementation, resume info should have at most a few entries
	// (e.g., one per directory being actively scanned), not one entry per
	// directory that has ever been visited.
	//
	// A reasonable upper bound for resume info size: each entry is roughly
	// "rootPath#subPath": "filePath". With temp paths ~50 chars, one entry is
	// ~150 bytes with JSON overhead. For 10 directories, accumulation would
	// mean ~1500+ bytes. A non-accumulating implementation should stay well
	// under that.
	const maxAcceptableResumeInfoSize = 300 // bytes - allows for ~2 entries max
	assert.LessOrEqual(t, maxResumeInfoSize, maxAcceptableResumeInfoSize,
		"Resume info grew to %d bytes during scan, suggesting accumulation across %d subdirectories. "+
			"Resume info should not accumulate entries for each subdirectory visited.",
		maxResumeInfoSize, numSubdirs)
}

func TestResumptionSkipsAlreadyScannedFiles(t *testing.T) {
	ctx := trContext.Background()

	// Create a directory with files that have predictable alphabetical order.
	rootDir, err := os.MkdirTemp("", "trufflehog-resumption-test")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(rootDir) })

	// Create files with predictable names for sorting.
	files := []string{"aaa.txt", "bbb.txt", "ccc.txt", "ddd.txt"}
	for _, name := range files {
		filePath := filepath.Join(rootDir, name)
		err := os.WriteFile(filePath, []byte("content of "+name), 0644)
		require.NoError(t, err)
	}

	conn, err := anypb.New(&sourcespb.Filesystem{})
	require.NoError(t, err)

	// Initialize the source.
	s := Source{}
	err = s.Init(ctx, "test resumption", 0, 0, true, conn, 1)
	require.NoError(t, err)

	// Pre-set the resume point to simulate a previous interrupted scan.
	// Setting it to bbb.txt means we should skip aaa.txt and bbb.txt,
	// and only scan ccc.txt and ddd.txt.
	resumePoint := filepath.Join(rootDir, "bbb.txt")
	s.SetEncodedResumeInfoFor(rootDir, resumePoint)

	// Run the scan.
	reporter := sourcestest.TestReporter{}
	err = s.ChunkUnit(ctx, sources.CommonSourceUnit{ID: rootDir}, &reporter)
	require.NoError(t, err)

	// Collect scanned file names.
	scannedFiles := make(map[string]bool)
	for _, chunk := range reporter.Chunks {
		file := chunk.SourceMetadata.GetFilesystem().GetFile()
		scannedFiles[filepath.Base(file)] = true
	}

	// Assert only files after the resume point were scanned.
	assert.False(t, scannedFiles["aaa.txt"], "aaa.txt should have been skipped (before resume point)")
	assert.False(t, scannedFiles["bbb.txt"], "bbb.txt should have been skipped (the resume point itself)")
	assert.True(t, scannedFiles["ccc.txt"], "ccc.txt should have been scanned (after resume point)")
	assert.True(t, scannedFiles["ddd.txt"], "ddd.txt should have been scanned (after resume point)")
	assert.Equal(t, 2, len(reporter.Chunks), "expected exactly 2 files to be scanned")
}

func TestResumptionWithNestedDirectories(t *testing.T) {
	ctx := trContext.Background()

	// Create a nested directory structure:
	// root/
	//   aaa/
	//     file1.txt
	//   bbb/
	//     file2.txt
	//   ccc/
	//     file3.txt
	rootDir, err := os.MkdirTemp("", "trufflehog-resumption-nested-test")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(rootDir) })

	dirs := []string{"aaa", "bbb", "ccc"}
	for i, dir := range dirs {
		dirPath := filepath.Join(rootDir, dir)
		err := os.Mkdir(dirPath, 0755)
		require.NoError(t, err)

		filePath := filepath.Join(dirPath, fmt.Sprintf("file%d.txt", i+1))
		err = os.WriteFile(filePath, []byte(fmt.Sprintf("content of file%d", i+1)), 0644)
		require.NoError(t, err)
	}

	conn, err := anypb.New(&sourcespb.Filesystem{})
	require.NoError(t, err)

	// Initialize the source.
	s := Source{}
	err = s.Init(ctx, "test resumption nested", 0, 0, true, conn, 1)
	require.NoError(t, err)

	// Pre-set the resume point to bbb/file2.txt.
	// This should skip aaa/file1.txt and bbb/file2.txt, only scanning ccc/file3.txt.
	resumePoint := filepath.Join(rootDir, "bbb", "file2.txt")
	s.SetEncodedResumeInfoFor(rootDir, resumePoint)

	// Run the scan.
	reporter := sourcestest.TestReporter{}
	err = s.ChunkUnit(ctx, sources.CommonSourceUnit{ID: rootDir}, &reporter)
	require.NoError(t, err)

	// Collect scanned file names.
	scannedFiles := make(map[string]bool)
	for _, chunk := range reporter.Chunks {
		file := chunk.SourceMetadata.GetFilesystem().GetFile()
		scannedFiles[filepath.Base(file)] = true
	}

	// Assert only file3.txt was scanned.
	assert.False(t, scannedFiles["file1.txt"], "file1.txt should have been skipped (in aaa/, before resume point)")
	assert.False(t, scannedFiles["file2.txt"], "file2.txt should have been skipped (the resume point itself)")
	assert.True(t, scannedFiles["file3.txt"], "file3.txt should have been scanned (in ccc/, after resume point)")
	assert.Equal(t, 1, len(reporter.Chunks), "expected exactly 1 file to be scanned")
}

func TestResumptionWithOutOfSubtreeResumePoint(t *testing.T) {
	ctx := trContext.Background()

	// Create a directory structure:
	// root/
	//   aaa/
	//     file1.txt
	//   bbb/
	//     file2.txt
	//   ccc/
	//     file3.txt
	//
	// This test verifies correct behavior when scanDir is called for a directory
	// with a resume point OUTSIDE that directory's subtree. Since os.ReadDir
	// returns entries sorted by filename, directories that lexicographically
	// precede the resume point were already fully scanned and should be skipped.
	rootDir, err := os.MkdirTemp("", "trufflehog-resumption-subtree-test")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(rootDir) })

	dirs := []string{"aaa", "bbb", "ccc"}
	for i, dir := range dirs {
		dirPath := filepath.Join(rootDir, dir)
		err := os.Mkdir(dirPath, 0755)
		require.NoError(t, err)

		filePath := filepath.Join(dirPath, fmt.Sprintf("file%d.txt", i+1))
		err = os.WriteFile(filePath, []byte(fmt.Sprintf("content of file%d", i+1)), 0644)
		require.NoError(t, err)
	}

	conn, err := anypb.New(&sourcespb.Filesystem{})
	require.NoError(t, err)

	// Initialize the source.
	s := Source{}
	err = s.Init(ctx, "test resumption subtree", 0, 0, true, conn, 1)
	require.NoError(t, err)

	// Pre-set the resume point to bbb/file2.txt using aaaDir as the key.
	// This simulates an edge case where scanDir is called directly for a
	// directory with a resume point outside its subtree.
	aaaDir := filepath.Join(rootDir, "aaa")
	resumePoint := filepath.Join(rootDir, "bbb", "file2.txt")
	s.SetEncodedResumeInfoFor(aaaDir, resumePoint)

	// Scan the aaa directory with a resume point outside its subtree.
	reporter := sourcestest.TestReporter{}
	err = s.ChunkUnit(ctx, sources.CommonSourceUnit{ID: aaaDir}, &reporter)
	require.NoError(t, err)

	// Collect scanned file names.
	scannedFiles := make(map[string]bool)
	for _, chunk := range reporter.Chunks {
		file := chunk.SourceMetadata.GetFilesystem().GetFile()
		scannedFiles[filepath.Base(file)] = true
	}

	// file1.txt should NOT be scanned because aaa/ comes before bbb/
	// lexicographically, meaning aaa/ would have been fully processed
	// before reaching the resume point.
	assert.False(t, scannedFiles["file1.txt"],
		"file1.txt should NOT be scanned because aaa/ comes before resume point bbb/file2.txt lexicographically")
	assert.Equal(t, 0, len(reporter.Chunks),
		"expected 0 files to be scanned since aaa/ was already fully processed before the resume point")
}

// createTempFile is a helper function to create a temporary file in the given
// directory with the provided contents. If dir is "", the operating system's
// temp directory is used.
func createTempFile(dir string, contents string) (*os.File, func(), error) {
	tmpfile, err := os.CreateTemp(dir, "trufflehogtest")
	if err != nil {
		return nil, nil, err
	}

	if _, err := tmpfile.Write([]byte(contents)); err != nil {
		_ = os.Remove(tmpfile.Name())
		return nil, nil, err
	}
	if err := tmpfile.Close(); err != nil {
		_ = os.Remove(tmpfile.Name())
		return nil, nil, err
	}
	return tmpfile, func() { _ = os.Remove(tmpfile.Name()) }, nil
}

// createTempDir is a helper function to create a temporary directory in the
// given directory with files containing the provided contents. If dir is "",
// the operating system's temp directory is used.
func createTempDir(dir string, contents ...string) (string, func(), error) {
	tmpdir, err := os.MkdirTemp(dir, "trufflehogtest")
	if err != nil {
		return "", nil, err
	}

	for _, content := range contents {
		if _, _, err := createTempFile(tmpdir, content); err != nil {
			_ = os.RemoveAll(tmpdir)
			return "", nil, err
		}
	}
	return tmpdir, func() { _ = os.RemoveAll(tmpdir) }, nil
}
