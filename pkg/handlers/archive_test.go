package handlers

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"math/rand"
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/h2non/filetype"
	"github.com/stretchr/testify/assert"
	diskbufferreader "github.com/trufflesecurity/disk-buffer-reader"

	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

func TestArchiveHandler(t *testing.T) {
	tests := map[string]struct {
		archiveURL     string
		expectedChunks int
		matchString    string
	}{
		"gzip-single": {
			"https://raw.githubusercontent.com/bill-rich/bad-secrets/master/one-zip.gz",
			1,
			"AKIAYVP4CIPPH5TNP3SW",
		},
		"gzip-nested": {
			"https://raw.githubusercontent.com/bill-rich/bad-secrets/master/double-zip.gz",
			1,
			"AKIAYVP4CIPPH5TNP3SW",
		},
		"gzip-too-deep": {
			"https://raw.githubusercontent.com/bill-rich/bad-secrets/master/six-zip.gz",
			0,
			"",
		},
		"tar-single": {
			"https://raw.githubusercontent.com/bill-rich/bad-secrets/master/one.tar",
			1,
			"AKIAYVP4CIPPH5TNP3SW",
		},
		"tar-nested": {
			"https://raw.githubusercontent.com/bill-rich/bad-secrets/master/two.tar",
			1,
			"AKIAYVP4CIPPH5TNP3SW",
		},
		"tar-too-deep": {
			"https://raw.githubusercontent.com/bill-rich/bad-secrets/master/six.tar",
			0,
			"",
		},
		"targz-single": {
			"https://raw.githubusercontent.com/bill-rich/bad-secrets/master/tar-archive.tar.gz",
			1,
			"AKIAYVP4CIPPH5TNP3SW",
		},
		"gzip-large": {
			"https://raw.githubusercontent.com/bill-rich/bad-secrets/master/FifteenMB.gz",
			1543,
			"AKIAYVP4CIPPH5TNP3SW",
		},
		"zip-single": {
			"https://raw.githubusercontent.com/bill-rich/bad-secrets/master/aws-canary-creds.zip",
			1,
			"AKIAYVP4CIPPH5TNP3SW",
		},
	}

	for name, testCase := range tests {
		t.Run(name, func(t *testing.T) {
			resp, err := http.Get(testCase.archiveURL)
			if err != nil || resp.StatusCode != http.StatusOK {
				t.Error(err)
			}
			defer resp.Body.Close()

			archive := Archive{}
			archive.New()

			newReader, err := diskbufferreader.New(resp.Body)
			if err != nil {
				t.Errorf("error creating reusable reader: %s", err)
			}
			archiveChan := archive.FromFile(logContext.Background(), newReader)

			count := 0
			re := regexp.MustCompile(testCase.matchString)
			matched := false
			for chunk := range archiveChan {
				count++
				if re.Match(chunk) {
					matched = true
				}
			}
			if !matched && len(testCase.matchString) > 0 {
				t.Errorf("%s: Expected string not found in archive.", name)
			}
			if count != testCase.expectedChunks {
				t.Errorf("%s: Unexpected number of chunks. Got %d, expected: %d", name, count, testCase.expectedChunks)
			}
		})
	}
}

func TestHandleFile(t *testing.T) {
	reporter := sources.ChanReporter{Ch: make(chan *sources.Chunk, 2)}

	// Context cancels the operation.
	canceledCtx, cancel := logContext.WithCancel(logContext.Background())
	cancel()
	reader, err := diskbufferreader.New(strings.NewReader("file"))
	assert.NoError(t, err)
	assert.False(t, HandleFile(canceledCtx, reader, &sources.Chunk{}, reporter))

	// Only one chunk is sent on the channel.
	// TODO: Embed a zip without making an HTTP request.
	resp, err := http.Get("https://raw.githubusercontent.com/bill-rich/bad-secrets/master/aws-canary-creds.zip")
	assert.NoError(t, err)
	defer resp.Body.Close()
	archive := Archive{}
	archive.New()
	reader, err = diskbufferreader.New(resp.Body)
	assert.NoError(t, err)

	assert.Equal(t, 0, len(reporter.Ch))
	assert.True(t, HandleFile(logContext.Background(), reader, &sources.Chunk{}, reporter))
	assert.Equal(t, 1, len(reporter.Ch))
}

func BenchmarkHandleFile(b *testing.B) {
	file, err := os.Open("testdata/test.tgz")
	assert.Nil(b, err)
	defer file.Close()

	archive := Archive{}
	archive.New()

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

func TestReadToMax(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected []byte
	}{
		{
			name:     "read full content within maxSize",
			input:    []byte("abcdefg"),
			expected: []byte("abcdefg"),
		},
		{
			name:     "read content larger than maxSize",
			input:    make([]byte, maxSize+10), // this creates a byte slice 10 bytes larger than maxSize
			expected: make([]byte, maxSize),
		},
		{
			name:     "empty input",
			input:    []byte(""),
			expected: []byte(""),
		},
	}

	a := &Archive{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := bytes.NewReader(tt.input)
			output, err := a.ReadToMax(logContext.Background(), reader)
			assert.Nil(t, err)

			assert.Equal(t, tt.expected, output)
		})
	}
}

func BenchmarkReadToMax(b *testing.B) {
	data := bytes.Repeat([]byte("a"), 1024*1000) // 1MB of data.
	reader := bytes.NewReader(data)
	a := &Archive{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StartTimer()
		_, _ = a.ReadToMax(logContext.Background(), reader)
		b.StopTimer()

		_, _ = reader.Seek(0, 0) // Reset the reader position.
		a.size = 0               // Reset archive size.
	}
}

func TestExtractDebContent(t *testing.T) {
	// Open the sample .deb file from the testdata folder.
	file, err := os.Open("testdata/test.deb")
	assert.Nil(t, err)
	defer file.Close()

	ctx := logContext.AddLogger(context.Background())
	a := &Archive{}

	reader, err := a.extractDebContent(ctx, file)
	assert.Nil(t, err)

	content, err := io.ReadAll(reader)
	assert.Nil(t, err)
	expectedLength := 1015582
	assert.Equal(t, expectedLength, len(string(content)))
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

func TestExtractRPMContent(t *testing.T) {
	// Open the sample .rpm file from the testdata folder.
	file, err := os.Open("testdata/test.rpm")
	assert.Nil(t, err)
	defer file.Close()

	ctx := logContext.AddLogger(context.Background())
	a := &Archive{}

	reader, err := a.extractRpmContent(ctx, file)
	assert.Nil(t, err)

	content, err := io.ReadAll(reader)
	assert.Nil(t, err)
	expectedLength := 1822720
	assert.Equal(t, expectedLength, len(string(content)))
}

func TestOpenInvalidArchive(t *testing.T) {
	reader := strings.NewReader("invalid archive")

	ctx := logContext.AddLogger(context.Background())
	a := &Archive{}

	archiveChan := make(chan []byte)

	err := a.openArchive(ctx, 0, reader, archiveChan)
	assert.Error(t, err)
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

			mime, reader, err := determineMimeType(tt.input)
			if err != nil && !tt.shouldFail {
				t.Fatalf("unexpected error: %v", err)
			}

			if !tt.shouldFail {
				assert.Equal(t, tt.expected, mime)
			}

			// Ensure the reader still contains all the original data.
			data, _ := io.ReadAll(reader)
			assert.Equal(t, originalData, data)
		})
	}
}
