package handlers

import (
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	diskbufferreader "github.com/trufflesecurity/disk-buffer-reader"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

func TestHandleFileCancelledContext(t *testing.T) {
	reporter := sources.ChanReporter{Ch: make(chan *sources.Chunk, 2)}

	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	reader, err := diskbufferreader.New(strings.NewReader("file"))
	assert.NoError(t, err)
	assert.Error(t, HandleFile(canceledCtx, reader, &sources.Chunk{}, reporter))
}

func TestHandleFile(t *testing.T) {
	reporter := sources.ChanReporter{Ch: make(chan *sources.Chunk, 2)}

	// Only one chunk is sent on the channel.
	// TODO: Embed a zip without making an HTTP request.
	resp, err := http.Get("https://raw.githubusercontent.com/bill-rich/bad-secrets/master/aws-canary-creds.zip")
	assert.NoError(t, err)
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}

	assert.Equal(t, 0, len(reporter.Ch))
	assert.NoError(t, HandleFile(context.Background(), resp.Body, &sources.Chunk{}, reporter))
	assert.Equal(t, 1, len(reporter.Ch))
}

func BenchmarkHandleFile(b *testing.B) {
	for i := 0; i < b.N; i++ {
		sourceChan := make(chan *sources.Chunk, 1)
		file, err := os.Open("testdata/test.tgz")
		assert.Nil(b, err)

		b.StartTimer()
		go func() {
			defer close(sourceChan)
			err := HandleFile(context.Background(), file, &sources.Chunk{}, sources.ChanReporter{Ch: sourceChan})
			assert.NoError(b, err)
		}()

		for range sourceChan {
		}
		b.StopTimer()
	}
}

func TestSkipArchive(t *testing.T) {
	file, err := os.Open("testdata/test.tgz")
	assert.Nil(t, err)

	chunkCh := make(chan *sources.Chunk)
	go func() {
		defer close(chunkCh)
		err := HandleFile(logContext.Background(), file, &sources.Chunk{}, sources.ChanReporter{Ch: chunkCh}, WithSkipArchives(true))
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
		err := HandleFile(logContext.Background(), file, &sources.Chunk{}, sources.ChanReporter{Ch: chunkCh})
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
		err := HandleFile(logContext.Background(), file, &sources.Chunk{}, sources.ChanReporter{Ch: chunkCh})
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
		err := HandleFile(logContext.Background(), file, &sources.Chunk{}, sources.ChanReporter{Ch: chunkCh})
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
		err := HandleFile(logContext.Background(), file, &sources.Chunk{}, sources.ChanReporter{Ch: chunkCh})
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

	chunkCh := make(chan *sources.Chunk)
	go func() {
		defer close(chunkCh)
		err := HandleFile(logContext.Background(), file, &sources.Chunk{}, sources.ChanReporter{Ch: chunkCh})
		assert.NoError(t, err)
	}()

	wantCount := 4
	count := 0
	for range chunkCh {
		count++
	}
	assert.Equal(t, wantCount, count)
}
