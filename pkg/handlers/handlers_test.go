package handlers

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	stdctx "context"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	diskbufferreader "github.com/trufflesecurity/disk-buffer-reader"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

//go:embed testdata/aws-canary-creds.zip
var awsCanaryCredsZip []byte

//go:embed testdata/sm.zip
var smJSONZip []byte

func TestHandleFileCancelledContext(t *testing.T) {
	reporter := sources.ChanReporter{Ch: make(chan *sources.Chunk, 2)}

	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	reader, err := diskbufferreader.New(strings.NewReader("file"))
	assert.NoError(t, err)
	assert.Error(t, HandleFile(canceledCtx, reader, &sources.Chunk{}, reporter))
}

func TestHandleFile(t *testing.T) {
	reporter := sources.ChanReporter{Ch: make(chan *sources.Chunk, 513)}

	// Only one chunk is sent on the channel.
	assert.Equal(t, 0, len(reporter.Ch))
	assert.NoError(t, HandleFile(context.Background(), bytes.NewReader(awsCanaryCredsZip), &sources.Chunk{}, reporter))
	assert.Equal(t, 1, len(reporter.Ch))
}

// Fetched over HTTP; the ~5 MB upstream fixture would notably grow pkg/handlers/testdata/ if embedded.
func TestHandleHTTPJson(t *testing.T) {
	resp, err := http.Get("https://raw.githubusercontent.com/trufflesecurity/trufflehog-test-assets/main/sm_random_data.json")
	assert.NoError(t, err)
	defer func() {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
	}()

	chunkCh := make(chan *sources.Chunk, 1)
	go func() {
		defer close(chunkCh)
		err := HandleFile(context.Background(), resp.Body, &sources.Chunk{}, sources.ChanReporter{Ch: chunkCh})
		assert.NoError(t, err)
	}()

	wantCount := 513
	count := 0
	for range chunkCh {
		count++
	}
	assert.Equal(t, wantCount, count)
}

func TestHandleHTTPJsonZip(t *testing.T) {
	chunkCh := make(chan *sources.Chunk, 1)
	go func() {
		defer close(chunkCh)
		err := HandleFile(context.Background(), bytes.NewReader(smJSONZip), &sources.Chunk{}, sources.ChanReporter{Ch: chunkCh})
		assert.NoError(t, err)
	}()

	wantCount := 513
	count := 0
	for range chunkCh {
		count++
	}
	assert.Equal(t, wantCount, count)
}

func BenchmarkHandleHTTPJsonZip(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		func() {
			chunkCh := make(chan *sources.Chunk, 1)

			b.StartTimer()
			go func() {
				defer close(chunkCh)
				err := HandleFile(context.Background(), bytes.NewReader(smJSONZip), &sources.Chunk{}, sources.ChanReporter{Ch: chunkCh})
				assert.NoError(b, err)
			}()

			for range chunkCh {
			}

			b.StopTimer()
		}()
	}
}

func BenchmarkHandleFile(b *testing.B) {
	file, err := os.Open("testdata/test.tgz")
	assert.Nil(b, err)
	defer func() { _ = file.Close() }()

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sourceChan := make(chan *sources.Chunk, 1)
		b.StartTimer()
		go func() {
			defer close(sourceChan)
			err := HandleFile(context.Background(), file, &sources.Chunk{}, sources.ChanReporter{Ch: sourceChan})
			assert.NoError(b, err)
		}()

		for range sourceChan {
		}
		b.StopTimer()

		_, err = file.Seek(0, io.SeekStart)
		assert.NoError(b, err)
	}
}

func TestSkipArchive(t *testing.T) {
	file, err := os.Open("testdata/test.tgz")
	assert.Nil(t, err)

	chunkCh := make(chan *sources.Chunk)
	go func() {
		defer close(chunkCh)
		err := HandleFile(context.Background(), file, &sources.Chunk{}, sources.ChanReporter{Ch: chunkCh}, WithSkipArchives(true))
		assert.NoError(t, err)
	}()

	wantCount := 0
	count := 0
	for range chunkCh {
		count++
	}
	assert.Equal(t, wantCount, count)
}

func TestHandleNestedArchives(t *testing.T) {
	file, err := os.Open("testdata/nested-dirs.zip")
	assert.Nil(t, err)

	chunkCh := make(chan *sources.Chunk)
	go func() {
		defer close(chunkCh)
		err := HandleFile(context.Background(), file, &sources.Chunk{}, sources.ChanReporter{Ch: chunkCh})
		assert.NoError(t, err)
	}()

	wantCount := 8
	count := 0
	for range chunkCh {
		count++
	}
	assert.Equal(t, wantCount, count)
}

func TestHandleCompressedZip(t *testing.T) {
	file, err := os.Open("testdata/example.zip.gz")
	assert.Nil(t, err)

	chunkCh := make(chan *sources.Chunk)
	go func() {
		defer close(chunkCh)
		err := HandleFile(context.Background(), file, &sources.Chunk{}, sources.ChanReporter{Ch: chunkCh})
		assert.NoError(t, err)
	}()

	wantCount := 2
	count := 0
	for range chunkCh {
		count++
	}
	assert.Equal(t, wantCount, count)
}

func TestHandleNestedCompressedArchive(t *testing.T) {
	file, err := os.Open("testdata/nested-compressed-archive.tar.gz")
	assert.Nil(t, err)

	chunkCh := make(chan *sources.Chunk)
	go func() {
		defer close(chunkCh)
		err := HandleFile(context.Background(), file, &sources.Chunk{}, sources.ChanReporter{Ch: chunkCh})
		assert.NoError(t, err)
	}()

	wantCount := 4
	count := 0
	for range chunkCh {
		count++
	}
	assert.Equal(t, wantCount, count)
}

func TestExtractTarContent(t *testing.T) {
	file, err := os.Open("testdata/test.tgz")
	assert.Nil(t, err)

	chunkCh := make(chan *sources.Chunk)
	go func() {
		defer close(chunkCh)
		err := HandleFile(context.Background(), file, &sources.Chunk{}, sources.ChanReporter{Ch: chunkCh})
		assert.NoError(t, err)
	}()

	wantCount := 4
	count := 0
	for range chunkCh {
		count++
	}
	assert.Equal(t, wantCount, count)
}

func TestNestedDirArchive(t *testing.T) {
	file, err := os.Open("testdata/dir-archive.zip")
	assert.Nil(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sourceChan := make(chan *sources.Chunk, 1)

	go func() {
		defer close(sourceChan)
		err := HandleFile(ctx, file, &sources.Chunk{}, sources.ChanReporter{Ch: sourceChan})
		assert.NoError(t, err)
	}()

	count := 0
	want := 4
	for range sourceChan {
		count++
	}
	assert.Equal(t, want, count)
}

func TestHandleFileRPM(t *testing.T) {
	wantChunkCount := 179
	reporter := sources.ChanReporter{Ch: make(chan *sources.Chunk, wantChunkCount)}

	file, err := os.Open("testdata/test.rpm")
	assert.Nil(t, err)

	assert.Equal(t, 0, len(reporter.Ch))
	assert.NoError(t, HandleFile(context.Background(), file, &sources.Chunk{}, reporter))
	assert.Equal(t, wantChunkCount, len(reporter.Ch))
}

func TestHandleFileAR(t *testing.T) {
	wantChunkCount := 102
	reporter := sources.ChanReporter{Ch: make(chan *sources.Chunk, wantChunkCount)}

	file, err := os.Open("testdata/test.deb")
	assert.Nil(t, err)

	assert.Equal(t, 0, len(reporter.Ch))
	assert.NoError(t, HandleFile(context.Background(), file, &sources.Chunk{}, reporter))
	assert.Equal(t, wantChunkCount, len(reporter.Ch))
}

func TestHandleFileMSG(t *testing.T) {
	wantChunkCount := 5
	reporter := sources.ChanReporter{Ch: make(chan *sources.Chunk, wantChunkCount)}

	file, err := os.Open("testdata/test.msg")
	require.NoError(t, err)

	assert.Empty(t, reporter.Ch)
	assert.NoError(t, HandleFile(context.Background(), file, &sources.Chunk{}, reporter))
	assert.Equal(t, wantChunkCount, len(reporter.Ch))
}

func TestHandleFileDOC(t *testing.T) {
	wantChunkCount := 3
	reporter := sources.ChanReporter{Ch: make(chan *sources.Chunk, wantChunkCount)}

	file, err := os.Open("testdata/test.doc")
	require.NoError(t, err)

	assert.Empty(t, reporter.Ch)
	assert.NoError(t, HandleFile(context.Background(), file, &sources.Chunk{}, reporter))
	assert.Equal(t, wantChunkCount, len(reporter.Ch))
}

func BenchmarkHandleAR(b *testing.B) {
	file, err := os.Open("testdata/test.deb")
	assert.Nil(b, err)
	defer func() { _ = file.Close() }()

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sourceChan := make(chan *sources.Chunk, 1)

		b.StartTimer()
		go func() {
			defer close(sourceChan)
			err := HandleFile(context.Background(), file, &sources.Chunk{}, sources.ChanReporter{Ch: sourceChan})
			assert.NoError(b, err)
		}()

		for range sourceChan {
		}
		b.StopTimer()

		_, err = file.Seek(0, io.SeekStart)
		assert.NoError(b, err)
	}
}

func TestHandleFileNonArchive(t *testing.T) {
	wantChunkCount := 6
	reporter := sources.ChanReporter{Ch: make(chan *sources.Chunk, wantChunkCount)}

	file, err := os.Open("testdata/nonarchive.txt")
	assert.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	assert.NoError(t, HandleFile(ctx, file, &sources.Chunk{}, reporter))
	assert.NoError(t, err)
	assert.Equal(t, wantChunkCount, len(reporter.Ch))
}

func TestExtractTarContentWithEmptyFile(t *testing.T) {
	file, err := os.Open("testdata/testdir.zip")
	assert.Nil(t, err)

	chunkCh := make(chan *sources.Chunk, 1)
	go func() {
		defer close(chunkCh)
		err := HandleFile(context.Background(), file, &sources.Chunk{}, sources.ChanReporter{Ch: chunkCh})
		assert.NoError(t, err)
	}()

	wantCount := 4
	count := 0
	for range chunkCh {
		count++
	}
	assert.Equal(t, wantCount, count)
}

func TestHandleTar(t *testing.T) {
	file, err := os.Open("testdata/test.tar")
	assert.Nil(t, err)
	defer func() { _ = file.Close() }()

	chunkCh := make(chan *sources.Chunk, 1)
	go func() {
		defer close(chunkCh)
		err := HandleFile(context.Background(), file, &sources.Chunk{}, sources.ChanReporter{Ch: chunkCh})
		assert.NoError(t, err)
	}()

	wantCount := 1
	count := 0
	for range chunkCh {
		count++
	}
	assert.Equal(t, wantCount, count)
}

func BenchmarkHandleTar(b *testing.B) {
	file, err := os.Open("testdata/test.tar")
	assert.Nil(b, err)
	defer func() { _ = file.Close() }()

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sourceChan := make(chan *sources.Chunk, 1)

		b.StartTimer()
		go func() {
			defer close(sourceChan)
			err := HandleFile(context.Background(), file, &sources.Chunk{}, sources.ChanReporter{Ch: sourceChan})
			assert.NoError(b, err)
		}()

		for range sourceChan {
		}
		b.StopTimer()

		_, err = file.Seek(0, io.SeekStart)
		assert.NoError(b, err)
	}
}

// Fetched over HTTP; the ~18 MB upstream fixture would substantially grow pkg/handlers/testdata/ if embedded.
func TestHandleLargeHTTPJson(t *testing.T) {
	resp, err := http.Get("https://raw.githubusercontent.com/trufflesecurity/trufflehog-test-assets/main/md_random_data.json.zip")
	if !assert.NoError(t, err) {
		return
	}

	defer func() {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
	}()

	chunkCh := make(chan *sources.Chunk, 1)
	go func() {
		defer close(chunkCh)
		err := HandleFile(context.Background(), resp.Body, &sources.Chunk{}, sources.ChanReporter{Ch: chunkCh})
		assert.NoError(t, err)
	}()

	wantCount := 5121
	count := 0
	for range chunkCh {
		count++
	}
	assert.Equal(t, wantCount, count)
}

func TestHandlePipe(t *testing.T) {
	r, w := io.Pipe()

	go func() {
		defer func() { _ = w.Close() }()
		file, err := os.Open("testdata/test.tar")
		assert.NoError(t, err)
		defer func() { _ = file.Close() }()
		_, err = io.Copy(w, file)
		assert.NoError(t, err)
	}()

	chunkCh := make(chan *sources.Chunk, 1)
	go func() {
		defer close(chunkCh)
		err := HandleFile(context.Background(), r, &sources.Chunk{}, sources.ChanReporter{Ch: chunkCh})
		assert.NoError(t, err)
	}()

	wantCount := 1
	count := 0
	for range chunkCh {
		count++
	}
	assert.Equal(t, wantCount, count)
}

func TestHandleZipCommandStdoutPipe(t *testing.T) {
	cmd := exec.Command("zip", "-j", "-", "testdata/nested-dirs.zip")
	stdout, err := cmd.StdoutPipe()
	assert.NoError(t, err)

	err = cmd.Start()
	assert.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	chunkCh := make(chan *sources.Chunk, 1)
	go func() {
		defer close(chunkCh)
		err := HandleFile(ctx, stdout, &sources.Chunk{}, sources.ChanReporter{Ch: chunkCh})
		assert.NoError(t, err)
	}()

	wantCount := 8
	count := 0
	for range chunkCh {
		count++
	}

	// cmd.Wait() should be called after all the reading from the pipe is done.
	// https://cs.opensource.google/go/go/+/refs/tags/go1.23.2:src/os/exec/exec.go;l=1051-1053
	err = cmd.Wait()
	assert.NoError(t, err)

	assert.Equal(t, wantCount, count)
}

func TestHandleGitCatFile(t *testing.T) {
	tests := []struct {
		name           string
		fileName       string
		fileSize       int
		supportedType  bool
		expectedChunks int
	}{
		{
			name:           "LargeBlob",
			fileName:       "largefile.bin",
			fileSize:       50 * 1024 * 1024, // 50 MB
			supportedType:  true,
			expectedChunks: 5120,
		},
		{
			name:           "UnsupportedType",
			fileName:       "unsupported.so",
			fileSize:       1024 * 1024, // 1 MB
			supportedType:  false,
			expectedChunks: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up a temporary git repository with the specified file.
			var gitDir string
			if tt.supportedType {
				gitDir = setupTempGitRepo(t, tt.fileName, tt.fileSize)
			} else {
				gitDir = setupTempGitRepoWithUnsupportedFile(t, tt.fileName, tt.fileSize)
			}
			defer func() { _ = os.RemoveAll(gitDir) }()

			cmd := exec.Command("git", "-C", gitDir, "rev-parse", "HEAD")
			hashBytes, err := cmd.Output()
			assert.NoError(t, err, "Failed to get commit hash")
			commitHash := strings.TrimSpace(string(hashBytes))

			// Create a pipe to simulate the git cat-file stdout.
			cmd = exec.Command("git", "-C", gitDir, "cat-file", "blob", fmt.Sprintf("%s:%s", commitHash, tt.fileName))

			var stderr bytes.Buffer
			cmd.Stderr = &stderr

			stdout, err := cmd.StdoutPipe()
			assert.NoError(t, err, "Failed to create stdout pipe")

			err = cmd.Start()
			assert.NoError(t, err, "Failed to start git cat-file command")

			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()

			chunkCh := make(chan *sources.Chunk, 1000)

			go func() {
				defer close(chunkCh)
				err := HandleFile(ctx, stdout, &sources.Chunk{}, sources.ChanReporter{Ch: chunkCh}, WithSkipArchives(false))
				assert.NoError(t, err, "HandleFile should not return an error")
			}()

			count := 0
			for range chunkCh {
				count++
			}

			// cmd.Wait() should be called after all the reading from the pipe is done.
			// https://cs.opensource.google/go/go/+/refs/tags/go1.23.2:src/os/exec/exec.go;l=1051-1053
			err = cmd.Wait()
			assert.NoError(t, err, "git cat-file command should complete without error")

			assert.Equal(t, tt.expectedChunks, count, "Number of chunks should match the expected value")
		})
	}
}

func setupTempGitRepoWithUnsupportedFile(t *testing.T, fileName string, fileSize int) string {
	t.Helper()
	return setupTempGitRepoCommon(t, fileName, fileSize, true)
}

func setupTempGitRepo(t *testing.T, archiveName string, fileSize int) string {
	t.Helper()
	return setupTempGitRepoCommon(t, archiveName, fileSize, false)
}

func setupTempGitRepoCommon(t *testing.T, fileName string, fileSize int, isUnsupported bool) string {
	t.Helper()

	tempDir := t.TempDir()

	cmd := exec.Command("git", "init", tempDir)
	var initStderr bytes.Buffer
	cmd.Stderr = &initStderr
	err := cmd.Run()
	if err != nil {
		t.Fatalf("Failed to initialize git repository: %v, stderr: %s", err, initStderr.String())
	}

	cmds := [][]string{
		{"git", "-C", tempDir, "config", "user.name", "Test User"},
		{"git", "-C", tempDir, "config", "user.email", "test@example.com"},
		{"git", "-C", tempDir, "config", "commit.gpgsign", "false"},
	}

	for _, cmdArgs := range cmds {
		cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...) //nolint:gosec
		var cmdStderr bytes.Buffer
		cmd.Stderr = &cmdStderr
		err := cmd.Run()
		if err != nil {
			t.Fatalf("Failed to set git config: %v, stderr: %s", err, cmdStderr.String())
		}
	}

	filePath := filepath.Join(tempDir, fileName)

	// Create the file with appropriate content.
	f, err := os.Create(filePath)
	if err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}
	defer func() { _ = f.Close() }()

	if isUnsupported {
		// Write ELF header for unsupported file.
		// https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.eheader.html
		elfHeader := []byte{
			0x7f, 'E', 'L', 'F', // ELF magic number
			2,                   // 64-bit format
			1,                   // Little endian
			1,                   // Current version of ELF
			0,                   // Target OS ABI
			0,                   // ABI Version
			0, 0, 0, 0, 0, 0, 0, // 7 bytes of padding
			3, 0, // Relocatable file
			0x3e, 0, // AMD x86-64 architecture
			1, 0, 0, 0, // ELF version
			0, 0, 0, 0, 0, 0, 0, 0, // Entry point
			0, 0, 0, 0, 0, 0, 0, 0, // Program header offset
			0, 0, 0, 0, 0, 0, 0, 0, // Section header offset
		}
		_, err = f.Write(elfHeader)
		if err != nil {
			t.Fatalf("Failed to write ELF header: %v", err)
		}
	} else {
		// Write ZIP content for supported file.
		zipWriter := zip.NewWriter(f)
		header := &zip.FileHeader{
			Name:   "largefile.txt",
			Method: zip.Store, // No compression
		}
		zipFileWriter, err := zipWriter.CreateHeader(header)
		if err != nil {
			t.Fatalf("Failed to create file in ZIP archive: %v", err)
		}

		dataChunk := bytes.Repeat([]byte("A"), 1024) // 1KB chunk
		totalWritten := 0
		for totalWritten < fileSize {
			remaining := fileSize - totalWritten
			if remaining < len(dataChunk) {
				_, err = zipFileWriter.Write(dataChunk[:remaining])
				if err != nil {
					t.Fatalf("Failed to write to inner file in ZIP archive: %v", err)
				}
				totalWritten += remaining
			} else {
				_, err = zipFileWriter.Write(dataChunk)
				if err != nil {
					t.Fatalf("Failed to write to inner file in ZIP archive: %v", err)
				}
				totalWritten += len(dataChunk)
			}
		}

		if err := zipWriter.Close(); err != nil {
			t.Fatalf("Failed to close ZIP writer: %v", err)
		}
	}

	// Add and commit the file to Git.
	cmd = exec.Command("git", "-C", tempDir, "add", fileName)
	var addStderr bytes.Buffer
	cmd.Stderr = &addStderr
	err = cmd.Run()
	if err != nil {
		t.Fatalf("Failed to add file to git: %v, stderr: %s", err, addStderr.String())
	}

	cmd = exec.Command("git", "-C", tempDir, "commit", "-m", "Add file")
	var commitStderr bytes.Buffer
	cmd.Stderr = &commitStderr
	err = cmd.Run()
	if err != nil {
		t.Fatalf("Failed to commit file to git: %v, stderr: %s", err, commitStderr.String())
	}

	return tempDir
}

func TestHandleFileNewFileReaderFailure(t *testing.T) {
	customReader := iotest.ErrReader(errors.New("simulated newFileReader error"))

	chunkSkel := &sources.Chunk{}
	chunkCh := make(chan *sources.Chunk)
	reporter := sources.ChanReporter{Ch: chunkCh}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := HandleFile(ctx, customReader, chunkSkel, reporter)

	assert.Error(t, err, "HandleFile should return an error when newFileReader fails")
}

// errorInjectingReader is a custom io.Reader that injects an error after reading a certain number of bytes.
type errorInjectingReader struct {
	reader        io.Reader
	injectAfter   int64 // Number of bytes after which to inject the error
	injected      bool
	bytesRead     int64
	errorToInject error
}

func (eir *errorInjectingReader) Read(p []byte) (int, error) {
	if eir.injectAfter > 0 && eir.bytesRead >= eir.injectAfter && !eir.injected {
		eir.injected = true
		return 0, eir.errorToInject
	}

	n, err := eir.reader.Read(p)
	eir.bytesRead += int64(n)
	return n, err
}

// TestHandleGitCatFileWithPipeError tests that when an error is injected during the HandleFile processing,
// the error is reported and the git cat-file command completes successfully.
func TestHandleGitCatFileWithPipeError(t *testing.T) {
	fileName := "largefile_with_error.bin"
	fileSize := 100 * 1024               // 100 KB
	injectErrorAfter := int64(50 * 1024) // Inject error after 50 KB
	simulatedError := errors.New("simulated error during newFileReader")

	gitDir := setupTempGitRepo(t, fileName, fileSize)
	defer func() { _ = os.RemoveAll(gitDir) }()

	commitHash := getGitCommitHash(t, gitDir)

	cmd := exec.Command("git", "-C", gitDir, "cat-file", "blob", fmt.Sprintf("%s:%s", commitHash, fileName))

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	stdout, err := cmd.StdoutPipe()
	assert.NoError(t, err, "Failed to create stdout pipe")

	err = cmd.Start()
	assert.NoError(t, err, "Failed to start git cat-file command")

	// Wrap the stdout with errorInjectingReader to simulate an error after reading injectErrorAfter bytes.
	wrappedReader := &errorInjectingReader{
		reader:        stdout,
		injectAfter:   injectErrorAfter,
		injected:      false,
		bytesRead:     0,
		errorToInject: simulatedError,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	chunkCh := make(chan *sources.Chunk, 1000)

	go func() {
		defer close(chunkCh)
		err = HandleFile(ctx, wrappedReader, &sources.Chunk{}, sources.ChanReporter{Ch: chunkCh}, WithSkipArchives(false))
		assert.NoError(t, err, "HandleFile should not return an error")
	}()

	for range chunkCh {
	}

	err = cmd.Wait()
	assert.NoError(t, err, "git cat-file command should complete without error")
}

// getGitCommitHash retrieves the current commit hash of the Git repository.
func getGitCommitHash(t *testing.T, gitDir string) string {
	t.Helper()
	cmd := exec.Command("git", "-C", gitDir, "rev-parse", "HEAD")
	hashBytes, err := cmd.Output()
	assert.NoError(t, err, "Failed to get commit hash")
	commitHash := strings.TrimSpace(string(hashBytes))
	return commitHash
}

type mockReporter struct{ reportedChunks int }

func (m *mockReporter) ChunkOk(context.Context, sources.Chunk) error {
	m.reportedChunks++
	return nil
}

func (m *mockReporter) ChunkErr(context.Context, error) error { return nil }

func TestHandleChunksWithError(t *testing.T) {
	tests := []struct {
		name                   string
		input                  []DataOrErr
		expectedErr            error
		expectedReportedChunks int
	}{
		{
			name:  "Non-Critical Error",
			input: []DataOrErr{{Err: ErrProcessingWarning}},
		},
		{
			name:        "Critical Error",
			input:       []DataOrErr{{Err: ErrProcessingFatal}},
			expectedErr: ErrProcessingFatal,
		},
		{
			name: "No Error",
			input: []DataOrErr{
				{Data: []byte("test data")},
				{Data: []byte("more data")},
			},
			expectedReportedChunks: 2,
		},
		{
			name:        "Context Canceled",
			input:       []DataOrErr{{Err: stdctx.Canceled}},
			expectedErr: stdctx.Canceled,
		},
		{
			name:        "Context Deadline Exceeded",
			input:       []DataOrErr{{Err: stdctx.DeadlineExceeded}},
			expectedErr: stdctx.DeadlineExceeded,
		},
		{
			name:  "EOF Error",
			input: []DataOrErr{{Err: io.EOF}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			chunkSkel := &sources.Chunk{}
			reporter := new(mockReporter)

			dataErrChan := make(chan DataOrErr, len(tc.input))
			for _, de := range tc.input {
				dataErrChan <- de
			}
			close(dataErrChan)

			err := handleChunksWithError(ctx, dataErrChan, chunkSkel, reporter)

			if tc.expectedErr != nil {
				assert.ErrorIs(t, err, tc.expectedErr, "handleChunksWithError should return the expected error")
			} else {
				assert.NoError(t, err, "handleChunksWithError should not return an error for non-critical errors")
			}

			assert.Equal(t, tc.expectedReportedChunks, reporter.reportedChunks, "should have reported the expected number of chunks")
		})
	}
}

// mockChunkReader creates a ChunkReader that returns predefined chunks.
// Each chunk has data and contentSize (contentSize is used to determine
// how many newlines to count for line tracking).
func mockChunkReader(chunks []sources.ChunkResult) sources.ChunkReader {
	return func(ctx context.Context, reader io.Reader) <-chan sources.ChunkResult {
		ch := make(chan sources.ChunkResult, len(chunks))
		for _, c := range chunks {
			ch <- c
		}
		close(ch)
		return ch
	}
}

// TestPopulateChunkLineNumber verifies that populateChunkLineNumber correctly clones
// metadata and sets line numbers for different metadata types.
// countingReader counts the bytes read through it. It deliberately does not
// implement io.Seeker, so HandleFile buffers it the way it buffers a pipe or an
// HTTP response body.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// pngContent returns size bytes that mimetype detects as image/png, which the
// default handler skips because ".png" is an ignored extension. The body is
// random so it stays large after gzip compression.
func pngContent(size int) []byte {
	data := make([]byte, size)
	_, _ = rand.New(rand.NewSource(1)).Read(data)
	copy(data, "\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89")
	return data
}

func gzipContent(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, err := w.Write(data)
	require.NoError(t, err)
	require.NoError(t, w.Close())
	return buf.Bytes()
}

func tarContent(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := tar.NewWriter(&buf)
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		require.NoError(t, w.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(files[name]))}))
		_, err := w.Write(files[name])
		require.NoError(t, err)
	}
	require.NoError(t, w.Close())
	return buf.Bytes()
}

// handleCounting runs HandleFile over data and returns how many bytes it read
// and the data of every chunk it reported.
func handleCounting(t *testing.T, data []byte, options ...func(*fileHandlingConfig)) (int64, [][]byte) {
	t.Helper()
	reader := &countingReader{r: bytes.NewReader(data)}
	chunkCh := make(chan *sources.Chunk, 1024)
	var chunks [][]byte
	done := make(chan struct{})
	go func() {
		defer close(done)
		for chunk := range chunkCh {
			chunks = append(chunks, chunk.Data)
		}
	}()
	err := HandleFile(context.Background(), reader, &sources.Chunk{}, sources.ChanReporter{Ch: chunkCh}, options...)
	close(chunkCh)
	<-done
	require.NoError(t, err)
	return reader.n, chunks
}

func TestHandleFileDrainSkipped(t *testing.T) {
	const size = 8 << 20
	// The handler detects the MIME type from the first few KiB. A skipped file
	// that is not drained must cost no more than one buffered read past that.
	const maxUndrainedRead = 64 << 10

	tests := []struct {
		name      string
		data      []byte
		options   []func(*fileHandlingConfig)
		wantDrain bool
	}{
		{name: "default drains skipped content", data: pngContent(size), wantDrain: true},
		{name: "true drains skipped content", data: pngContent(size), options: []func(*fileHandlingConfig){WithDrainSkipped(true)}, wantDrain: true},
		{name: "false stops after detection", data: pngContent(size), options: []func(*fileHandlingConfig){WithDrainSkipped(false)}},
		{name: "default drains skipped content inside gzip", data: gzipContent(t, pngContent(size)), wantDrain: true},
		{name: "false stops after detection inside gzip", data: gzipContent(t, pngContent(size)), options: []func(*fileHandlingConfig){WithDrainSkipped(false)}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			read, chunks := handleCounting(t, tc.data, tc.options...)
			assert.Empty(t, chunks, "skipped content must not produce chunks")
			if tc.wantDrain {
				assert.Equal(t, int64(len(tc.data)), read, "skipped content should be read to EOF")
				return
			}
			assert.LessOrEqual(t, read, int64(maxUndrainedRead), "skipped content should not be read to EOF")
		})
	}
}

func TestHandleFileDrainSkippedLeavesScannedContentUnchanged(t *testing.T) {
	text := []byte(strings.Repeat("aws_access_key_id = AKIAEXAMPLEEXAMPLE00\n", 1<<15))
	inputs := map[string][]byte{
		"text":                text,
		"tar of png and text": tarContent(t, map[string][]byte{"image": pngContent(1 << 20), "notes.txt": text}),
		"gzip of text":        gzipContent(t, text),
	}
	entries, err := os.ReadDir("testdata")
	require.NoError(t, err)
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join("testdata", entry.Name()))
		require.NoError(t, err)
		inputs["testdata/"+entry.Name()] = data
	}

	for name, data := range inputs {
		t.Run(name, func(t *testing.T) {
			defaultRead, defaultChunks := handleCounting(t, data)
			undrainedRead, undrainedChunks := handleCounting(t, data, WithDrainSkipped(false))
			assert.Equal(t, defaultChunks, undrainedChunks)
			assert.Equal(t, defaultRead, undrainedRead)
		})
	}
}

func TestPopulateChunkLineNumber(t *testing.T) {
	tests := []struct {
		name       string
		metadata   *source_metadatapb.MetaData
		lineNumber int64
		getLine    func(*source_metadatapb.MetaData) int64
	}{
		{
			name: "Filesystem metadata",
			metadata: &source_metadatapb.MetaData{
				Data: &source_metadatapb.MetaData_Filesystem{
					Filesystem: &source_metadatapb.Filesystem{File: "test.txt"},
				},
			},
			lineNumber: 42,
			getLine: func(m *source_metadatapb.MetaData) int64 {
				return m.Data.(*source_metadatapb.MetaData_Filesystem).Filesystem.Line
			},
		},
		{
			name: "Git metadata",
			metadata: &source_metadatapb.MetaData{
				Data: &source_metadatapb.MetaData_Git{
					Git: &source_metadatapb.Git{File: "test.go"},
				},
			},
			lineNumber: 100,
			getLine: func(m *source_metadatapb.MetaData) int64 {
				return m.Data.(*source_metadatapb.MetaData_Git).Git.Line
			},
		},
		{
			name: "Github metadata",
			metadata: &source_metadatapb.MetaData{
				Data: &source_metadatapb.MetaData_Github{
					Github: &source_metadatapb.Github{File: "test.py"},
				},
			},
			lineNumber: 200,
			getLine: func(m *source_metadatapb.MetaData) int64 {
				return m.Data.(*source_metadatapb.MetaData_Github).Github.Line
			},
		},
		{
			name:       "nil metadata",
			metadata:   nil,
			lineNumber: 10,
			getLine:    func(m *source_metadatapb.MetaData) int64 { return 0 },
		},
		{
			name: "zero line number",
			metadata: &source_metadatapb.MetaData{
				Data: &source_metadatapb.MetaData_Filesystem{
					Filesystem: &source_metadatapb.Filesystem{File: "test.txt"},
				},
			},
			lineNumber: 0,
			getLine: func(m *source_metadatapb.MetaData) int64 {
				return m.Data.(*source_metadatapb.MetaData_Filesystem).Filesystem.Line
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			chunk := &sources.Chunk{SourceMetadata: tc.metadata}
			originalMetadata := tc.metadata

			populateChunkLineNumber(chunk, tc.lineNumber)

			if tc.metadata == nil || tc.lineNumber == 0 {
				// Metadata should remain unchanged
				assert.Equal(t, originalMetadata, chunk.SourceMetadata)
				return
			}

			// Verify the line number is set correctly
			actualLine := tc.getLine(chunk.SourceMetadata)
			assert.Equal(t, tc.lineNumber, actualLine,
				"line number should be set to %d, got %d", tc.lineNumber, actualLine)

			// Verify the original is not modified (metadata was cloned)
			originalLine := tc.getLine(tc.metadata)
			assert.Equal(t, int64(0), originalLine,
				"original metadata should not be modified, but line is %d", originalLine)
		})
	}
}
