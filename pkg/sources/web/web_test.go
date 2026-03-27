package web

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

func TestWebSource_HappyPath(t *testing.T) {
	// Create a test server that returns a simple HTML page.
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(`<!DOCTYPE html><html><head><title>Test Page</title></head><body>Hello, world!</body></html>`))
	}))
	defer testServer.Close()

	// Build the web source configuration.
	webConfig := &sourcespb.Web{
		Urls:  []string{testServer.URL},
		Crawl: false,
		Depth: 0,
		Delay: 0,
	}

	conn := &anypb.Any{}
	err := conn.MarshalFrom(webConfig)
	assert.NoError(t, err)

	s := &Source{}
	err = s.Init(context.TODO(), "test source", 0, 0, false, conn, 1)
	assert.NoError(t, err)

	var wg sync.WaitGroup
	chunksChan := make(chan *sources.Chunk, 1)
	chunkCounter := 0

	// Collect all chunks.
	var chunks []*sources.Chunk
	wg.Add(1)
	go func() {
		defer wg.Done()
		for chunk := range chunksChan {
			assert.NotEmpty(t, chunk)
			chunkCounter++
			chunks = append(chunks, chunk)
		}
	}()

	err = s.Chunks(context.TODO(), chunksChan)
	assert.NoError(t, err)

	close(chunksChan)
	wg.Wait()

	assert.Equal(t, 1, chunkCounter)
	chunk := chunks[0]

	// Check the chunk data.
	assert.Contains(t, string(chunk.Data), "Hello, world!")
	// Verify the metadata.
	meta, ok := chunk.SourceMetadata.Data.(*source_metadatapb.MetaData_Web)
	assert.True(t, ok, "expected web metadata")
	assert.Equal(t, "Test Page", meta.Web.PageTitle)
	assert.Equal(t, "text/html; charset=utf-8", meta.Web.ContentType)
	assert.Equal(t, int64(1), meta.Web.Depth) // default 1 depth
	assert.NotEmpty(t, meta.Web.Timestamp)
}
