package handlers

import (
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

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
	assert.NoError(t, HandleFile(canceledCtx, reader, &sources.Chunk{}, reporter))
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
	assert.NoError(t, HandleFile(logContext.Background(), reader, &sources.Chunk{}, reporter))
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
		err := HandleFile(ctx, reader, &sources.Chunk{}, sources.ChanReporter{Ch: chunkCh}, WithSkipArchives(true))
		assert.NoError(t, err)
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
		err := HandleFile(ctx, reader, &sources.Chunk{}, sources.ChanReporter{Ch: chunkCh})
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

func TestHandleFileRPM(t *testing.T) {
	wantChunkCount := 179
	reporter := sources.ChanReporter{Ch: make(chan *sources.Chunk, wantChunkCount)}

	file, err := os.Open("testdata/test.rpm")
	assert.Nil(t, err)
	defer file.Close()

	reader, err := diskbufferreader.New(file)
	assert.NoError(t, err)

	assert.Equal(t, 0, len(reporter.Ch))
	assert.NoError(t, HandleFile(logContext.Background(), reader, &sources.Chunk{}, reporter))
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
	assert.NoError(t, HandleFile(logContext.Background(), reader, &sources.Chunk{}, reporter))
	assert.Equal(t, wantChunkCount, len(reporter.Ch))
}
