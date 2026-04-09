package web

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

// helper: marshal a *sourcespb.Web config into an *anypb.Any and Init a Source.
func initSource(t *testing.T, cfg *sourcespb.Web, concurrency int) *Source {
	t.Helper()
	conn := &anypb.Any{}
	require.NoError(t, conn.MarshalFrom(cfg))
	s := &Source{}
	require.NoError(t, s.Init(context.TODO(), "test-source", 0, 0, false, conn, concurrency))
	return s
}

// helper: run Chunks and collect all emitted chunks.
func collectChunks(t *testing.T, s *Source) []*sources.Chunk {
	t.Helper()
	chunksChan := make(chan *sources.Chunk, 16)
	var wg sync.WaitGroup
	var chunks []*sources.Chunk
	wg.Add(1)
	go func() {
		defer wg.Done()
		for c := range chunksChan {
			chunks = append(chunks, c)
		}
	}()
	require.NoError(t, s.Chunks(context.TODO(), chunksChan))
	close(chunksChan)
	wg.Wait()
	return chunks
}

// Init validation

func TestInit_NoURL(t *testing.T) {
	conn := &anypb.Any{}
	require.NoError(t, conn.MarshalFrom(&sourcespb.Web{}))
	s := &Source{}
	err := s.Init(context.TODO(), "test", 0, 0, false, conn, 1)
	assert.Error(t, err)
}

func TestInit_DefaultUserAgent(t *testing.T) {
	conn := &anypb.Any{}
	require.NoError(t, conn.MarshalFrom(&sourcespb.Web{
		Urls: []string{"http://example.com"},
	}))
	s := &Source{}
	require.NoError(t, s.Init(context.TODO(), "test", 0, 0, false, conn, 1))
	assert.Contains(t, s.conn.GetUserAgent(), "trufflehog")
}

func TestInit_CustomUserAgent(t *testing.T) {
	conn := &anypb.Any{}
	require.NoError(t, conn.MarshalFrom(&sourcespb.Web{
		Urls:      []string{"http://example.com"},
		UserAgent: "my-bot/1.0",
	}))
	s := &Source{}
	require.NoError(t, s.Init(context.TODO(), "test", 0, 0, false, conn, 1))
	assert.Equal(t, "my-bot/1.0", s.conn.GetUserAgent())
}

func TestInit_ZeroConcurrencyDefaultsToOne(t *testing.T) {
	conn := &anypb.Any{}
	require.NoError(t, conn.MarshalFrom(&sourcespb.Web{
		Urls: []string{"http://example.com"},
	}))
	s := &Source{}
	require.NoError(t, s.Init(context.TODO(), "test", 0, 0, false, conn, 0))
	assert.Equal(t, 1, s.concurrency)
}

// URL validation

func TestInit_InvalidURL_MissingScheme(t *testing.T) {
	conn := &anypb.Any{}
	require.NoError(t, conn.MarshalFrom(&sourcespb.Web{
		Urls: []string{"example.com"},
	}))
	s := &Source{}
	err := s.Init(context.TODO(), "test", 0, 0, false, conn, 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing scheme")
}

func TestInit_InvalidURL_UnsupportedScheme(t *testing.T) {
	conn := &anypb.Any{}
	require.NoError(t, conn.MarshalFrom(&sourcespb.Web{
		Urls: []string{"ftp://example.com"},
	}))
	s := &Source{}
	err := s.Init(context.TODO(), "test", 0, 0, false, conn, 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported scheme")
}

func TestInit_InvalidURL_MissingHost(t *testing.T) {
	conn := &anypb.Any{}
	require.NoError(t, conn.MarshalFrom(&sourcespb.Web{
		Urls: []string{"http://"},
	}))
	s := &Source{}
	err := s.Init(context.TODO(), "test", 0, 0, false, conn, 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing host")
}

func TestInit_ValidURL_HTTP(t *testing.T) {
	conn := &anypb.Any{}
	require.NoError(t, conn.MarshalFrom(&sourcespb.Web{
		Urls: []string{"http://example.com"},
	}))
	s := &Source{}
	err := s.Init(context.TODO(), "test", 0, 0, false, conn, 1)
	assert.NoError(t, err)
}

func TestInit_ValidURL_HTTPS(t *testing.T) {
	conn := &anypb.Any{}
	require.NoError(t, conn.MarshalFrom(&sourcespb.Web{
		Urls: []string{"https://example.com"},
	}))
	s := &Source{}
	err := s.Init(context.TODO(), "test", 0, 0, false, conn, 1)
	assert.NoError(t, err)
}

func TestInit_DuplicateURL(t *testing.T) {
	conn := &anypb.Any{}
	require.NoError(t, conn.MarshalFrom(&sourcespb.Web{
		Urls: []string{"http://example.com", "http://example.com"},
	}))
	s := &Source{}
	err := s.Init(context.TODO(), "test", 0, 0, false, conn, 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate URL")
}

// Partial failure and error handling

func TestChunks_PartialFailure(t *testing.T) {
	// Test that when one URL fails and another succeeds, we still process the successful one
	// and return an error at the end.

	goodSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><head><title>Good</title></head><body>Good data</body></html>`)
	}))
	defer goodSrv.Close()

	// This URL will fail (port 1 is unreachable)
	badURL := "http://localhost:1"

	s := initSource(t, &sourcespb.Web{
		Urls: []string{badURL, goodSrv.URL},
		Timeout: 2,
	}, 1)

	chunksChan := make(chan *sources.Chunk, 16)

	// Chunks should return an error due to the bad URL
	err := s.Chunks(context.TODO(), chunksChan)
	close(chunksChan)

	// Collect chunks that were successfully emitted
	var chunks []*sources.Chunk
	for c := range chunksChan {
		chunks = append(chunks, c)
	}

	// Should have an error (the bad URL)
	assert.Error(t, err, "expected error from unreachable URL")

	// But should still have processed the good URL
	assert.NotEmpty(t, chunks, "expected chunks from the reachable URL despite one failure")

	// Verify the chunk is from the good URL
	meta := chunks[0].SourceMetadata.Data.(*source_metadatapb.MetaData_Web)
	assert.Contains(t, meta.Web.Url, "127.0.0.1", "chunk should be from the working URL")
	assert.Equal(t, "Good", meta.Web.PageTitle)
}

// Visit error propagation

func TestChunks_VisitErrorPropagated(t *testing.T) {
	// Test that Visit() errors on the seed URL are propagated, not silently swallowed.
	// Point to a URL that will definitely fail to connect.
	failURL := "http://localhost:1"  // Port 1 is unlikely to have a service; connection should be refused

	s := initSource(t, &sourcespb.Web{Urls: []string{failURL}, Timeout: 2}, 1)
	chunksChan := make(chan *sources.Chunk, 16)

	// Chunks() should return an error, not nil.
	err := s.Chunks(context.TODO(), chunksChan)
	close(chunksChan)

	// The error should be non-nil because the seed URL is unreachable.
	assert.Error(t, err, "expected Visit() error to be propagated")
	// We don't check the exact error message since it can vary by OS/network,
	// but it should be a network error, not a context error.
}

// Happy path

func TestChunks_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!DOCTYPE html><html><head><title>Test Page</title></head><body>Hello, world!</body></html>`)
	}))
	defer srv.Close()

	s := initSource(t, &sourcespb.Web{Urls: []string{srv.URL}}, 1)
	chunks := collectChunks(t, s)

	require.Equal(t, 1, len(chunks))
	chunk := chunks[0]

	assert.Contains(t, string(chunk.Data), "Hello, world!")

	meta, ok := chunk.SourceMetadata.Data.(*source_metadatapb.MetaData_Web)
	require.True(t, ok, "expected web metadata")
	assert.Equal(t, "Test Page", meta.Web.PageTitle)
	assert.Equal(t, "text/html; charset=utf-8", meta.Web.ContentType)
	assert.NotEmpty(t, meta.Web.Url)
	assert.NotEmpty(t, meta.Web.Timestamp)
}

func TestChunks_TimestampIsRFC3339(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><head><title>T</title></head><body>body</body></html>`)
	}))
	defer srv.Close()

	s := initSource(t, &sourcespb.Web{Urls: []string{srv.URL}}, 1)
	chunks := collectChunks(t, s)
	require.Equal(t, 1, len(chunks))

	meta := chunks[0].SourceMetadata.Data.(*source_metadatapb.MetaData_Web)
	_, err := time.Parse(time.RFC3339, meta.Web.Timestamp)
	assert.NoError(t, err, "timestamp must be valid RFC3339")
}

// Page title extraction

func TestExtractPageTitle_Normal(t *testing.T) {
	body := []byte(`<html><head><title>  Hello World  </title></head><body></body></html>`)
	assert.Equal(t, "Hello World", extractPageTitle(body))
}

func TestExtractPageTitle_Missing(t *testing.T) {
	body := []byte(`<html><head></head><body>no title</body></html>`)
	assert.Equal(t, "", extractPageTitle(body))
}

func TestExtractPageTitle_Empty(t *testing.T) {
	assert.Equal(t, "", extractPageTitle([]byte{}))
}

func TestExtractPageTitle_MalformedHTML(t *testing.T) {
	// html.Parse is lenient; just confirm it doesn't panic and returns something sensible.
	body := []byte(`<title>Partial`)
	title := extractPageTitle(body)
	// Go's html.Parse fills in missing closing tags, so the title is still parsed.
	assert.Equal(t, "Partial", title)
}

func TestExtractPageTitle_NonHTML(t *testing.T) {
	// Binary / JSON bodies must not panic.
	body := []byte(`{"secret": "abc123"}`)
	_ = extractPageTitle(body) // just confirm no panic
}

// Depth / crawl behaviour

// TestChunks_NoCrawl confirms that when Crawl=false only the seed page is
// fetched, even if the page contains an internal link.
func TestChunks_NoCrawl(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><head><title>Root</title></head><body>
			<a href="/page2">page 2</a>
		</body></html>`)
	})
	mux.HandleFunc("/page2", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><head><title>Page 2</title></head><body>Secret</body></html>`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// Crawl=false - only the seed URL is visited.
	s := initSource(t, &sourcespb.Web{Urls: []string{srv.URL}, Crawl: false}, 1)
	chunks := collectChunks(t, s)

	assert.Equal(t, 1, len(chunks), "expected only the root page when Crawl=false")
	meta := chunks[0].SourceMetadata.Data.(*source_metadatapb.MetaData_Web)
	assert.Equal(t, "Root", meta.Web.PageTitle)
}

// TestChunks_CrawlDepth1 confirms that with Crawl=true and Depth=1 the crawler
// visits the seed page and its direct links, but not grandchildren.
func TestChunks_CrawlDepth1(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><head><title>Root</title></head><body>
			<a href="/child">child</a>
		</body></html>`)
	})
	mux.HandleFunc("/child", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><head><title>Child</title></head><body>
			<a href="/grandchild">grandchild</a>
		</body></html>`)
	})
	mux.HandleFunc("/grandchild", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><head><title>Grandchild</title></head><body>deep</body></html>`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	s := initSource(t, &sourcespb.Web{Urls: []string{srv.URL}, Crawl: true, Depth: 2}, 1)
	chunks := collectChunks(t, s)

	titles := make(map[string]bool)
	for _, c := range chunks {
		meta := c.SourceMetadata.Data.(*source_metadatapb.MetaData_Web)
		titles[meta.Web.PageTitle] = true
	}

	assert.True(t, titles["Root"], "root page should be crawled")
	assert.True(t, titles["Child"], "child page should be crawled at depth 1")
	assert.False(t, titles["Grandchild"], "grandchild should NOT be crawled at depth 1")
}

// TestChunks_CrawlDepth2 confirms depth-2 traversal reaches grandchildren.
func TestChunks_CrawlDepth2(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><head><title>Root</title></head><body>
			<a href="/child">child</a>
		</body></html>`)
	})
	mux.HandleFunc("/child", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><head><title>Child</title></head><body>
			<a href="/grandchild">grandchild</a>
		</body></html>`)
	})
	mux.HandleFunc("/grandchild", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><head><title>Grandchild</title></head><body>deep</body></html>`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	s := initSource(t, &sourcespb.Web{Urls: []string{srv.URL}, Crawl: true, Depth: 3}, 1)
	chunks := collectChunks(t, s)

	titles := make(map[string]bool)
	for _, c := range chunks {
		meta := c.SourceMetadata.Data.(*source_metadatapb.MetaData_Web)
		titles[meta.Web.PageTitle] = true
	}

	assert.True(t, titles["Root"])
	assert.True(t, titles["Child"])
	assert.True(t, titles["Grandchild"])
}

// TestChunks_CrossDomainLinksIgnored ensures that links pointing to a different
// hostname are not followed. httptest.NewServer always binds to 127.0.0.1, so
// we cannot spin up a second "external" server on a different IP in a portable
// way. Instead we embed a link to an unreachable external hostname directly in
// the page HTML and assert that no chunk with that hostname is ever produced.
func TestChunks_CrossDomainLinksIgnored(t *testing.T) {
	const externalURL = "http://external.example.invalid/secret"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><head><title>Seed</title></head><body>
			<a href="%s">external link</a>
		</body></html>`, externalURL)
	}))
	defer srv.Close()

	s := initSource(t, &sourcespb.Web{Urls: []string{srv.URL}, Crawl: true, Depth: 1}, 1)
	chunks := collectChunks(t, s)

	for _, c := range chunks {
		meta := c.SourceMetadata.Data.(*source_metadatapb.MetaData_Web)
		assert.NotContains(t, meta.Web.Url, "external.example.invalid",
			"cross-domain URL must not appear in chunks")
	}
}

// Content types

func TestChunks_PlainTextPage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "API_KEY=supersecret")
	}))
	defer srv.Close()

	s := initSource(t, &sourcespb.Web{Urls: []string{srv.URL}}, 1)
	chunks := collectChunks(t, s)

	require.Equal(t, 1, len(chunks))
	assert.Contains(t, string(chunks[0].Data), "supersecret")

	meta := chunks[0].SourceMetadata.Data.(*source_metadatapb.MetaData_Web)
	assert.Equal(t, "text/plain", meta.Web.ContentType)
}

func TestChunks_JSONPage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"token":"ghp_supersecret"}`)
	}))
	defer srv.Close()

	s := initSource(t, &sourcespb.Web{Urls: []string{srv.URL}}, 1)
	chunks := collectChunks(t, s)

	require.Equal(t, 1, len(chunks))
	assert.Contains(t, string(chunks[0].Data), "ghp_supersecret")
}

// Error / edge cases

func TestChunks_ServerReturns404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	s := initSource(t, &sourcespb.Web{Urls: []string{srv.URL}}, 1)
	// colly treats 4xx as errors and fires OnError; no chunk should be emitted.
	chunks := collectChunks(t, s)
	assert.Empty(t, chunks, "a 404 response should not produce a chunk")
}

func TestChunks_EmptyBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// no body written
	}))
	defer srv.Close()

	s := initSource(t, &sourcespb.Web{Urls: []string{srv.URL}}, 1)
	chunks := collectChunks(t, s)
	// An empty but 200-OK response should still produce a chunk (body == "").
	require.Equal(t, 1, len(chunks))
	assert.Empty(t, chunks[0].Data)
}

// Duplicate link deduplication

// TestChunks_DuplicateLinksVisitedOnce ensures that the same URL appearing
// multiple times in a page is only fetched once.
func TestChunks_DuplicateLinksVisitedOnce(t *testing.T) {
	hitCount := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><head><title>Root</title></head><body>
			<a href="/dup">link1</a>
			<a href="/dup">link2</a>
			<a href="/dup">link3</a>
		</body></html>`)
	})
	mux.HandleFunc("/dup", func(w http.ResponseWriter, r *http.Request) {
		hitCount++
		fmt.Fprint(w, `<html><head><title>Dup</title></head><body>dup</body></html>`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	s := initSource(t, &sourcespb.Web{Urls: []string{srv.URL}, Crawl: true, Depth: 0}, 1)
	_ = collectChunks(t, s)

	assert.Equal(t, 1, hitCount, "duplicate links should only be fetched once")
}

// Robots.txt

func TestChunks_RobotsTxtRespected(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "User-agent: *\nDisallow: /secret\n")
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><head><title>Root</title></head><body>
			<a href="/secret">secret</a>
		</body></html>`)
	})
	secretVisited := false
	mux.HandleFunc("/secret", func(w http.ResponseWriter, r *http.Request) {
		secretVisited = true
		fmt.Fprint(w, `<html><head><title>Secret</title></head><body>private</body></html>`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	s := initSource(t, &sourcespb.Web{
		Urls: []string{srv.URL}, Crawl: true, Depth: 1, IgnoreRobots: false,
	}, 1)
	_ = collectChunks(t, s)

	assert.False(t, secretVisited, "/secret must not be crawled when disallowed by robots.txt")
}

func TestChunks_IgnoreRobotsTxt(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "User-agent: *\nDisallow: /secret\n")
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><head><title>Root</title></head><body>
			<a href="/secret">secret</a>
		</body></html>`)
	})
	secretVisited := false
	mux.HandleFunc("/secret", func(w http.ResponseWriter, r *http.Request) {
		secretVisited = true
		fmt.Fprint(w, `<html><head><title>Secret</title></head><body>private</body></html>`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	s := initSource(t, &sourcespb.Web{
		Urls: []string{srv.URL}, Crawl: true, Depth: 2, IgnoreRobots: true,
	}, 1)
	_ = collectChunks(t, s)

	assert.True(t, secretVisited, "/secret should be crawled when IgnoreRobots=true")
}

