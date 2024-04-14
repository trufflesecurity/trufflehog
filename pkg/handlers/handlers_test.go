package handlers

import (
	"archive/tar"
	"bytes"
	"encoding/binary"
	"io"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/h2non/filetype"
	"github.com/stretchr/testify/assert"
	diskbufferreader "github.com/trufflesecurity/disk-buffer-reader"

	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

func TestHandleFileCancelledContext(t *testing.T) {
	reporter := sources.ChanReporter{Ch: make(chan *sources.Chunk, 2)}

	canceledCtx, cancel := logContext.WithCancel(logContext.Background())
	cancel()
	reader, err := diskbufferreader.New(strings.NewReader("file"))
	assert.NoError(t, err)
	assert.False(t, HandleFile(canceledCtx, reader, &sources.Chunk{}, reporter))
}

func TestHandleFile(t *testing.T) {
	reporter := sources.ChanReporter{Ch: make(chan *sources.Chunk, 2)}

	// Only one chunk is sent on the channel.
	// TODO: Embed a zip without making an HTTP request.
	resp, err := http.Get("https://raw.githubusercontent.com/bill-rich/bad-secrets/master/aws-canary-creds.zip")
	assert.NoError(t, err)
	defer resp.Body.Close()

	reader, err := diskbufferreader.New(resp.Body)
	assert.NoError(t, err)

	assert.Equal(t, 0, len(reporter.Ch))
	assert.True(t, HandleFile(logContext.Background(), reader, &sources.Chunk{}, reporter))
	assert.Equal(t, 1, len(reporter.Ch))
}

func BenchmarkHandleFile(b *testing.B) {
	file, err := os.Open("testdata/test.tgz")
	assert.Nil(b, err)
	defer file.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sourceChan := make(chan *sources.Chunk, 1)
		reader, err := diskbufferreader.New(file)
		assert.NoError(b, err)

		b.StartTimer()

		go func() {
			defer close(sourceChan)
			HandleFile(logContext.Background(), reader, &sources.Chunk{}, sources.ChanReporter{Ch: sourceChan})
		}()

		for range sourceChan {
		}

		b.StopTimer()
	}
}

func TestHandleFileSkipBinaries(t *testing.T) {
	filename := createBinaryArchive(t)
	defer os.Remove(filename)

	file, err := os.Open(filename)
	assert.NoError(t, err)

	reader, err := diskbufferreader.New(file)
	assert.NoError(t, err)

	ctx, cancel := logContext.WithTimeout(logContext.Background(), 5*time.Second)
	defer cancel()
	sourceChan := make(chan *sources.Chunk, 1)

	go func() {
		defer close(sourceChan)
		HandleFile(ctx, reader, &sources.Chunk{}, sources.ChanReporter{Ch: sourceChan}, WithSkipBinaries(true))
	}()

	count := 0
	for range sourceChan {
		count++
	}
	// The binary archive should not be scanned.
	assert.Equal(t, 0, count)
}

func createBinaryArchive(t *testing.T) string {
	t.Helper()

	f, err := os.CreateTemp("", "testbinary")
	assert.NoError(t, err)
	defer os.Remove(f.Name())

	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	randomBytes := make([]byte, 1024)
	_, err = r.Read(randomBytes)
	assert.NoError(t, err)

	_, err = f.Write(randomBytes)
	assert.NoError(t, err)

	// Create and write some structured binary data (e.g., integers, floats)
	for i := 0; i < 10; i++ {
		err = binary.Write(f, binary.LittleEndian, int32(rand.Intn(1000)))
		assert.NoError(t, err)
		err = binary.Write(f, binary.LittleEndian, rand.Float64())
		assert.NoError(t, err)
	}

	tarFile, err := os.Create("example.tar")
	if err != nil {
		t.Fatal(err)
	}
	defer tarFile.Close()

	// Create a new tar archive.
	tarWriter := tar.NewWriter(tarFile)
	defer tarWriter.Close()

	fileInfo, err := f.Stat()
	assert.NoError(t, err)

	header, err := tar.FileInfoHeader(fileInfo, "")
	assert.NoError(t, err)

	err = tarWriter.WriteHeader(header)
	assert.NoError(t, err)

	fileContent, err := os.ReadFile(f.Name())
	assert.NoError(t, err)

	_, err = tarWriter.Write(fileContent)
	assert.NoError(t, err)

	return tarFile.Name()
}

func TestSkipArchive(t *testing.T) {
	file, err := os.Open("testdata/test.tgz")
	assert.Nil(t, err)
	defer file.Close()

	reader, err := diskbufferreader.New(file)
	assert.NoError(t, err)

	ctx := logContext.Background()

	chunkCh := make(chan *sources.Chunk)
	go func() {
		defer close(chunkCh)
		ok := HandleFile(ctx, reader, &sources.Chunk{}, sources.ChanReporter{Ch: chunkCh}, WithSkipArchives(true))
		assert.False(t, ok)
	}()

	wantCount := 0
	count := 0
	for range chunkCh {
		count++
	}
	assert.Equal(t, wantCount, count)
}

func TestExtractTarContent(t *testing.T) {
	file, err := os.Open("testdata/test.tgz")
	assert.Nil(t, err)
	defer file.Close()

	reader, err := diskbufferreader.New(file)
	assert.NoError(t, err)

	ctx := logContext.Background()

	chunkCh := make(chan *sources.Chunk)
	go func() {
		defer close(chunkCh)
		ok := HandleFile(ctx, reader, &sources.Chunk{}, sources.ChanReporter{Ch: chunkCh})
		assert.True(t, ok)
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
	defer file.Close()

	reader, err := diskbufferreader.New(file)
	assert.NoError(t, err)

	ctx, cancel := logContext.WithTimeout(logContext.Background(), 5*time.Second)
	defer cancel()
	sourceChan := make(chan *sources.Chunk, 1)

	go func() {
		defer close(sourceChan)
		HandleFile(ctx, reader, &sources.Chunk{}, sources.ChanReporter{Ch: sourceChan})
	}()

	count := 0
	want := 4
	for range sourceChan {
		count++
	}
	assert.Equal(t, want, count)
}

func TestDetermineMimeType(t *testing.T) {
	filetype.AddMatcher(filetype.NewType("txt", "text/plain"), func(buf []byte) bool {
		return strings.HasPrefix(string(buf), "text:")
	})

	pngBytes := []byte("\x89PNG\r\n\x1a\n")
	jpegBytes := []byte{0xFF, 0xD8, 0xFF}
	textBytes := []byte("text: This is a plain text")
	rpmBytes := []byte("\xed\xab\xee\xdb")

	tests := []struct {
		name       string
		input      io.Reader
		expected   mimeType
		shouldFail bool
	}{
		{
			name:       "PNG file",
			input:      bytes.NewReader(pngBytes),
			expected:   mimeType("image/png"),
			shouldFail: false,
		},
		{
			name:       "JPEG file",
			input:      bytes.NewReader(jpegBytes),
			expected:   mimeType("image/jpeg"),
			shouldFail: false,
		},
		{
			name:       "Text file",
			input:      bytes.NewReader(textBytes),
			expected:   mimeType("text/plain"),
			shouldFail: false,
		},
		{
			name:       "RPM file",
			input:      bytes.NewReader(rpmBytes),
			expected:   rpmMimeType,
			shouldFail: false,
		},
		{
			name:       "Truncated JPEG file",
			input:      io.LimitReader(bytes.NewReader(jpegBytes), 2),
			expected:   mimeType("unknown"),
			shouldFail: true,
		},
		{
			name:       "Empty reader",
			input:      bytes.NewReader([]byte{}),
			shouldFail: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			originalData, _ := io.ReadAll(io.TeeReader(tt.input, &bytes.Buffer{}))
			tt.input = bytes.NewReader(originalData) // Reset the reader

			mime, err := determineMimeType(tt.input)
			if err != nil && !tt.shouldFail {
				t.Fatalf("unexpected error: %v", err)
			}

			if !tt.shouldFail {
				assert.Equal(t, tt.expected, mime)
			}
		})
	}
}

func TestHandleFileRPM(t *testing.T) {
	wantChunkCount := 179
	reporter := sources.ChanReporter{Ch: make(chan *sources.Chunk, wantChunkCount)}

	file, err := os.Open("testdata/test.rpm")
	assert.Nil(t, err)
	defer file.Close()

	reader, err := diskbufferreader.New(file)
	assert.NoError(t, err)

	assert.Equal(t, 0, len(reporter.Ch))
	assert.True(t, HandleFile(logContext.Background(), reader, &sources.Chunk{}, reporter))
	assert.Equal(t, wantChunkCount, len(reporter.Ch))
}

func TestHandleFileAR(t *testing.T) {
	wantChunkCount := 102
	reporter := sources.ChanReporter{Ch: make(chan *sources.Chunk, wantChunkCount)}

	file, err := os.Open("testdata/test.deb")
	assert.Nil(t, err)
	defer file.Close()

	reader, err := diskbufferreader.New(file)
	assert.NoError(t, err)

	assert.Equal(t, 0, len(reporter.Ch))
	assert.True(t, HandleFile(logContext.Background(), reader, &sources.Chunk{}, reporter))
	assert.Equal(t, wantChunkCount, len(reporter.Ch))
}
