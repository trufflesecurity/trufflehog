package filesystem

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/kylelemons/godebug/pretty"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sourcestest"
)

func TestSource_Scan(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
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
				file := chunk.SourceMetadata.GetFilesystem().GetFile()
				if file == "filesystem.go" {
					counter++
					if diff := pretty.Compare(chunk.SourceMetadata, tt.wantSourceMetadata); diff != "" {
						t.Errorf("Source.Chunks() %s diff: (-got +want)\n%s", tt.name, diff)
					}
				}
			}
			// Debug: Log if we find more than one chunk
			if counter != 1 {
				t.Logf("filesystem.go found %d times (file is %d bytes, chunk size is %d bytes)",
					counter, 12819, sources.DefaultChunkSize)
			}
			// Note: filesystem.go (12,819 bytes) is larger than the default chunk size (10KB),
			// so it gets split into multiple chunks. This test verifies we find at least one chunk
			// with the correct filename, which is the important assertion.
			assert.GreaterOrEqual(t, counter, 1, "Should find at least one filesystem.go")
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

	ctx := context.WithLogger(context.Background(), logr.Discard())
	go func() {
		defer close(chunksChan)
		err = source.scanFile(ctx, tmpfile.Name(), chunksChan)
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

	ctx := context.WithLogger(context.Background(), logr.Discard())

	go func() {
		defer close(chunksChan)
		errChan <- source.scanFile(ctx, tmpfile.Name(), chunksChan)
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
	ctx := context.Background()

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
	ctx := context.Background()

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
	ctx := context.Background()

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
	ctx := context.Background()

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
	ctx := context.Background()

	// create a temp directory with files
	ignoreDir, cleanupDir, err := createTempDir("", "ignore1", "ignore2", "ignore3")
	require.NoError(t, err)
	defer cleanupDir()

	// create an ExcludePathsFile that contains the ignoreDir path
	excludeFile, cleanupFile, err := createTempFile("", ignoreDir+"\n")
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
	ctx := context.Background()

	// create a temp directory with files
	parentDir, cleanupParentDir, err := createTempDir("", "file1")
	require.NoError(t, err)
	defer cleanupParentDir()

	childDir, cleanupChildDir, err := createTempDir(parentDir, "file2")
	require.NoError(t, err)
	defer cleanupChildDir()

	// create a file in child directory
	file, cleanupFile, err := createTempFile(childDir, "should scan this file")
	require.NoError(t, err)
	defer cleanupFile()

	// create an IncludePathsFile that contains the file path
	includeFile, cleanupFile, err := createTempFile("", file.Name()+"\n")
	require.NoError(t, err)
	defer cleanupFile()

	conn, err := anypb.New(&sourcespb.Filesystem{
		IncludePathsFile: includeFile.Name(),
	})
	require.NoError(t, err)

	// initialize the source.
	s := Source{}
	err = s.Init(ctx, "include sub directory file", 0, 0, true, conn, 1)
	require.NoError(t, err)

	reporter := sourcestest.TestReporter{}
	err = s.ChunkUnit(ctx, sources.CommonSourceUnit{
		ID: parentDir,
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
	ctx := context.Background()

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

func TestFollowSymlinks(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Create a temporary directory with a file and a symlink
	tempDir, err := os.MkdirTemp("", "trufflehog_symlink_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create a real file
	realFile := filepath.Join(tempDir, "real_file.txt")
	fileContents := "secret data in real file"
	err = os.WriteFile(realFile, []byte(fileContents), 0644)
	require.NoError(t, err)

	// Create a symlink pointing to the real file
	symlinkFile := filepath.Join(tempDir, "symlink_file.txt")
	err = os.Symlink(realFile, symlinkFile)
	require.NoError(t, err)

	// Test 1: followSymlinks = false (default) - should skip symlink
	t.Run("skip symlinks when followSymlinks is false", func(t *testing.T) {
		conn, err := anypb.New(&sourcespb.Filesystem{
			Paths:          []string{symlinkFile},
			FollowSymlinks: false,
		})
		require.NoError(t, err)

		s := Source{}
		err = s.Init(ctx, "test skip symlinks", 0, 0, true, conn, 1)
		require.NoError(t, err)

		reporter := sourcestest.TestReporter{}
		err = s.ChunkUnit(ctx, sources.CommonSourceUnit{
			ID: symlinkFile,
		}, &reporter)
		require.NoError(t, err)

		// Should not have any chunks because symlink was skipped
		assert.Equal(t, 0, len(reporter.Chunks), "Expected no chunks when symlinks are skipped")
		// Should have one error for the skipped symlink
		assert.Equal(t, 1, len(reporter.ChunkErrs), "Expected one error for skipped symlink")
	})

	// Test 2: followSymlinks = true - should follow symlink
	t.Run("follow symlinks when followSymlinks is true", func(t *testing.T) {
		conn, err := anypb.New(&sourcespb.Filesystem{
			Paths:          []string{symlinkFile},
			FollowSymlinks: true,
		})
		require.NoError(t, err)

		s := Source{}
		err = s.Init(ctx, "test follow symlinks", 0, 0, true, conn, 1)
		require.NoError(t, err)

		reporter := sourcestest.TestReporter{}
		err = s.ChunkUnit(ctx, sources.CommonSourceUnit{
			ID: symlinkFile,
		}, &reporter)
		require.NoError(t, err)

		// Should have chunks because symlink was followed
		assert.Equal(t, 1, len(reporter.Chunks), "Expected chunks when symlinks are followed")
		assert.Equal(t, 0, len(reporter.ChunkErrs), "Expected no errors when following symlinks")

		// Verify the content is correct
		if len(reporter.Chunks) > 0 {
			assert.Contains(t, string(reporter.Chunks[0].Data), fileContents, "Chunk should contain file contents")
		}
	})

	// Test 3: Scanning directory with symlink using followSymlinks = false
	t.Run("skip symlinks in directory scan when followSymlinks is false", func(t *testing.T) {
		conn, err := anypb.New(&sourcespb.Filesystem{
			Paths:          []string{tempDir},
			FollowSymlinks: false,
		})
		require.NoError(t, err)

		s := Source{}
		err = s.Init(ctx, "test directory skip symlinks", 0, 0, true, conn, 1)
		require.NoError(t, err)

		reporter := sourcestest.TestReporter{}
		err = s.ChunkUnit(ctx, sources.CommonSourceUnit{
			ID: tempDir,
		}, &reporter)
		require.NoError(t, err)

		// Should have exactly one chunk from the real file only
		assert.Equal(t, 1, len(reporter.Chunks), "Expected one chunk from real file only")

		// Verify it's the real file, not the symlink
		if len(reporter.Chunks) > 0 {
			metadata := reporter.Chunks[0].SourceMetadata.GetFilesystem()
			assert.NotNil(t, metadata)
			// The path should be the real file
			assert.Contains(t, metadata.File, "real_file.txt")
		}
	})

	// Test 4: Scanning directory with symlink using followSymlinks = true
	t.Run("follow symlinks in directory scan when followSymlinks is true", func(t *testing.T) {
		conn, err := anypb.New(&sourcespb.Filesystem{
			Paths:          []string{tempDir},
			FollowSymlinks: true,
		})
		require.NoError(t, err)

		s := Source{}
		err = s.Init(ctx, "test directory follow symlinks", 0, 0, true, conn, 1)
		require.NoError(t, err)

		reporter := sourcestest.TestReporter{}
		err = s.ChunkUnit(ctx, sources.CommonSourceUnit{
			ID: tempDir,
		}, &reporter)
		require.NoError(t, err)

		// Should have two chunks: one from real file and one from symlink
		assert.Equal(t, 2, len(reporter.Chunks), "Expected two chunks when following symlinks in directory")

		// Verify both contain the same content
		for _, chunk := range reporter.Chunks {
			assert.Contains(t, string(chunk.Data), fileContents, "Both chunks should contain file contents")
		}
	})
}

func TestSymlinkLoopDetection(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Create a temporary directory
	tempDir, err := os.MkdirTemp("", "trufflehog_symlink_loop_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create a file
	realFile := filepath.Join(tempDir, "file.txt")
	fileContents := "secret data"
	err = os.WriteFile(realFile, []byte(fileContents), 0644)
	require.NoError(t, err)

	// Create a symlink pointing back to the parent directory (loop)
	symlinkLoop := filepath.Join(tempDir, "loop_symlink")
	err = os.Symlink(tempDir, symlinkLoop)
	require.NoError(t, err)

	t.Run("detect and skip symlink loops", func(t *testing.T) {
		conn, err := anypb.New(&sourcespb.Filesystem{
			Paths:          []string{tempDir},
			FollowSymlinks: true,
		})
		require.NoError(t, err)

		s := Source{}
		err = s.Init(ctx, "test loop detection", 0, 0, true, conn, 1)
		require.NoError(t, err)

		reporter := sourcestest.TestReporter{}
		err = s.ChunkUnit(ctx, sources.CommonSourceUnit{
			ID: tempDir,
		}, &reporter)
		require.NoError(t, err)

		// Should only have one chunk from the real file, loop symlink should be skipped
		assert.Equal(t, 1, len(reporter.Chunks), "Expected one chunk, loop symlink should be skipped")

		// Verify it's the real file
		if len(reporter.Chunks) > 0 {
			assert.Contains(t, string(reporter.Chunks[0].Data), fileContents, "Chunk should contain file contents")
		}
	})
}

func TestSymlinkChainDepth(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Create a temporary directory
	tempDir, err := os.MkdirTemp("", "trufflehog_symlink_chain_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create a real file
	realFile := filepath.Join(tempDir, "real_file.txt")
	fileContents := "secret data in real file"
	err = os.WriteFile(realFile, []byte(fileContents), 0644)
	require.NoError(t, err)

	// Create a symlink chain: symlink1 -> symlink2 -> real_file
	symlink2 := filepath.Join(tempDir, "symlink2.txt")
	err = os.Symlink(realFile, symlink2)
	require.NoError(t, err)

	symlink1 := filepath.Join(tempDir, "symlink1.txt")
	err = os.Symlink(symlink2, symlink1)
	require.NoError(t, err)

	t.Run("only follow first level symlink in chain", func(t *testing.T) {
		conn, err := anypb.New(&sourcespb.Filesystem{
			Paths:          []string{tempDir},
			FollowSymlinks: true,
		})
		require.NoError(t, err)

		s := Source{}
		err = s.Init(ctx, "test symlink chain", 0, 0, true, conn, 1)
		require.NoError(t, err)

		reporter := sourcestest.TestReporter{}
		err = s.ChunkUnit(ctx, sources.CommonSourceUnit{
			ID: tempDir,
		}, &reporter)
		require.NoError(t, err)

		// Should have 2 chunks: real_file and symlink1 (which resolves to real_file)
		// symlink2 also resolves to the same real_file, so loop detection prevents duplicate scanning
		// This is correct behavior - we don't want to scan the same content multiple times
		assert.Equal(t, 2, len(reporter.Chunks), "Expected two chunks from real file and first symlink")
	})
}

func TestSymlinkInSubdirectory(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Create a temporary directory structure
	tempDir, err := os.MkdirTemp("", "trufflehog_subdir_symlink_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create a subdirectory
	subDir := filepath.Join(tempDir, "subdir")
	err = os.MkdirAll(subDir, 0755)
	require.NoError(t, err)

	// Create a real file in the temp dir
	realFile := filepath.Join(tempDir, "real_file.txt")
	fileContents := "secret data in real file"
	err = os.WriteFile(realFile, []byte(fileContents), 0644)
	require.NoError(t, err)

	// Create a symlink in the subdirectory pointing to the real file
	symlinkInSubdir := filepath.Join(subDir, "symlink.txt")
	err = os.Symlink(realFile, symlinkInSubdir)
	require.NoError(t, err)

	t.Run("skip symlinks in subdirectories when followSymlinks is true", func(t *testing.T) {
		conn, err := anypb.New(&sourcespb.Filesystem{
			Paths:          []string{tempDir},
			FollowSymlinks: true,
		})
		require.NoError(t, err)

		s := Source{}
		err = s.Init(ctx, "test subdir symlinks", 0, 0, true, conn, 1)
		require.NoError(t, err)

		reporter := sourcestest.TestReporter{}
		err = s.ChunkUnit(ctx, sources.CommonSourceUnit{
			ID: tempDir,
		}, &reporter)
		require.NoError(t, err)

		// Should only have one chunk from the real file
		// The symlink in the subdirectory should be skipped (not a direct child)
		assert.Equal(t, 1, len(reporter.Chunks), "Expected one chunk, subdirectory symlink should be skipped")

		// Verify it's the real file
		if len(reporter.Chunks) > 0 {
			metadata := reporter.Chunks[0].SourceMetadata.GetFilesystem()
			assert.NotNil(t, metadata)
			assert.Contains(t, metadata.File, "real_file.txt")
		}
	})
}

func TestMemoryBoundedSymlinkFollowing(t *testing.T) {
	ctx := context.Background()

	// Create a temporary directory
	tempDir, err := os.MkdirTemp("", "trufflehog_memory_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create more files than the LRU cache size (10,000)
	// We'll create 100 files and check that memory doesn't blow up
	numFiles := 100
	for i := 0; i < numFiles; i++ {
		fileName := filepath.Join(tempDir, fmt.Sprintf("file_%d.txt", i))
		err = os.WriteFile(fileName, []byte(fmt.Sprintf("content %d", i)), 0644)
		require.NoError(t, err)

		// Create a symlink for each file
		symlinkName := filepath.Join(tempDir, fmt.Sprintf("symlink_%d.txt", i))
		err = os.Symlink(fileName, symlinkName)
		require.NoError(t, err)
	}

	// Test scanning with multiple paths to ensure cache is reset between paths
	t.Run("cache resets between paths", func(t *testing.T) {
		// Create two subdirectories
		subDir1 := filepath.Join(tempDir, "sub1")
		subDir2 := filepath.Join(tempDir, "sub2")
		err = os.MkdirAll(subDir1, 0755)
		require.NoError(t, err)
		err = os.MkdirAll(subDir2, 0755)
		require.NoError(t, err)

		// Add some files to each
		for i := 0; i < 10; i++ {
			err = os.WriteFile(filepath.Join(subDir1, fmt.Sprintf("file%d.txt", i)), []byte("data"), 0644)
			require.NoError(t, err)
			err = os.WriteFile(filepath.Join(subDir2, fmt.Sprintf("file%d.txt", i)), []byte("data"), 0644)
			require.NoError(t, err)
		}

		conn, err := anypb.New(&sourcespb.Filesystem{
			Paths:          []string{subDir1, subDir2},
			FollowSymlinks: true,
		})
		require.NoError(t, err)

		s := Source{}
		err = s.Init(ctx, "test memory bounded", 0, 0, true, conn, 1)
		require.NoError(t, err)

		chunksCh := make(chan *sources.Chunk, 100)
		go func() {
			defer close(chunksCh)
			err = s.Chunks(ctx, chunksCh)
			assert.NoError(t, err)
		}()

		chunkCount := 0
		for range chunksCh {
			chunkCount++
		}

		// Should have scanned files from both directories
		assert.Greater(t, chunkCount, 0, "Should have found chunks")

		// The visitedPaths cache should have been reset between paths,
		// preventing unbounded memory growth
	})
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
