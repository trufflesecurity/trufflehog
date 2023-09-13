package handlers

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"

	diskbufferreader "github.com/bill-rich/disk-buffer-reader"
	"github.com/stretchr/testify/assert"

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
		archiveChan := archive.FromFile(context.Background(), newReader)

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
	}
}

func TestHandleFile(t *testing.T) {
	ch := make(chan *sources.Chunk, 2)

	// Context cancels the operation.
	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	assert.False(t, HandleFile(canceledCtx, strings.NewReader("file"), &sources.Chunk{}, ch))

	// Only one chunk is sent on the channel.
	// TODO: Embed a zip without making an HTTP request.
	resp, err := http.Get("https://raw.githubusercontent.com/bill-rich/bad-secrets/master/aws-canary-creds.zip")
	assert.NoError(t, err)
	defer resp.Body.Close()
	archive := Archive{}
	archive.New()
	reader, err := diskbufferreader.New(resp.Body)
	assert.NoError(t, err)

	assert.Equal(t, 0, len(ch))
	assert.True(t, HandleFile(context.Background(), reader, &sources.Chunk{}, ch))
	assert.Equal(t, 1, len(ch))
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
			output, err := a.ReadToMax(context.Background(), reader)
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
		_, _ = a.ReadToMax(context.Background(), reader)
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

func TestExtractTarContent(t *testing.T) {
	file, err := os.Open("testdata/test.tgz")
	assert.Nil(t, err)
	defer file.Close()

	ctx := context.Background()

	chunkCh := make(chan *sources.Chunk)
	go func() {
		defer close(chunkCh)
		ok := HandleFile(ctx, file, &sources.Chunk{}, chunkCh)
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
