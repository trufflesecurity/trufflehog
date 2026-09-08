package httpx

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

const (
	secretPart1 = "SECRET"
	secretPart2 = "SPLIT"
	secret      = secretPart1 + secretPart2
)

// makeBody returns a body of roughly 2*size bytes with the secret straddling
// the boundary at `size`, so that a body large enough to be split across
// multiple chunks still yields the secret intact via the chunker's peek window.
func makeBody(size int) string {
	return strings.Join([]string{
		strings.Repeat("A", size-len(secretPart1)),
		secretPart1,
		secretPart2,
		strings.Repeat("A", size-len(secretPart2)),
	}, "")
}

// jsonl marshals each record to a single line, mimicking `httpx -json` output.
func jsonl(t *testing.T, records ...map[string]any) string {
	t.Helper()
	var sb strings.Builder
	for _, r := range records {
		b, err := json.Marshal(r)
		require.NoError(t, err)
		sb.Write(b)
		sb.WriteByte('\n')
	}
	return sb.String()
}

// runSource scans input and returns every chunk produced.
func runSource(t *testing.T, s *Source, input string) ([]*sources.Chunk, error) {
	t.Helper()

	chunksChan := make(chan *sources.Chunk, 64)

	var mu sync.Mutex
	var chunks []*sources.Chunk

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for c := range chunksChan {
			mu.Lock()
			chunks = append(chunks, c)
			mu.Unlock()
		}
	}()

	ctx := context.WithLogger(t.Context(), logr.Discard())
	err := s.scanReader(ctx, strings.NewReader(input), "test.jsonl", chunksChan, nil)
	close(chunksChan)
	wg.Wait()

	return chunks, err
}

// concat joins the data of every chunk so tests can assert on what the detector
// engine would actually see.
func concat(chunks []*sources.Chunk) string {
	var sb strings.Builder
	for _, c := range chunks {
		sb.Write(c.Data)
	}
	return sb.String()
}

func TestScanBodies(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		source      Source
		record      map[string]any
		expectFound bool
	}{
		{
			name:        "small body",
			record:      map[string]any{"url": "https://example.com/", "body": secret},
			expectFound: true,
		},
		{
			name:        "body spanning multiple chunks",
			record:      map[string]any{"url": "https://example.com/", "body": makeBody(sources.DefaultChunkSize * 10)},
			expectFound: true,
		},
		{
			name:        "null body",
			record:      map[string]any{"url": "https://example.com/", "body": nil},
			expectFound: false,
		},
		{
			name:        "missing body",
			record:      map[string]any{"url": "https://example.com/", "status_code": 404},
			expectFound: false,
		},
		{
			name:        "empty body",
			record:      map[string]any{"url": "https://example.com/", "body": ""},
			expectFound: false,
		},
		{
			name:        "failed request with no body",
			record:      map[string]any{"input": "example.com", "failed": true, "error": "connection refused", "body": nil},
			expectFound: false,
		},
		{
			name:        "base64 body",
			source:      Source{base64Body: true},
			record:      map[string]any{"url": "https://example.com/", "body": base64.StdEncoding.EncodeToString([]byte(secret))},
			expectFound: true,
		},
		{
			name:        "base64 body that is not valid base64 falls back to raw",
			source:      Source{base64Body: true},
			record:      map[string]any{"url": "https://example.com/", "body": secret + " not base64!"},
			expectFound: true,
		},
		{
			name:        "headless body ignored by default",
			record:      map[string]any{"url": "https://example.com/", "headless_body": secret},
			expectFound: false,
		},
		{
			name:        "headless body scanned when enabled",
			source:      Source{includeHeadlessBody: true},
			record:      map[string]any{"url": "https://example.com/", "headless_body": secret},
			expectFound: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			src := tc.source
			chunks, err := runSource(t, &src, jsonl(t, tc.record))
			require.NoError(t, err)

			if tc.expectFound {
				assert.Contains(t, concat(chunks), secret)
			} else {
				assert.Empty(t, chunks)
			}
		})
	}
}

// TestOnlyBodyIsScanned is the central guarantee of this source: no field other
// than the response body is ever handed to the detector engine. Headers,
// request dumps, titles and redirect chains routinely echo credentials that are
// not actually exposed by the target, so scanning them produces noise.
func TestOnlyBodyIsScanned(t *testing.T) {
	t.Parallel()

	const nonBodySecret = "NOTABODYSECRETVALUE"

	record := map[string]any{
		"url":          "https://example.com/",
		"input":        "example.com" + nonBodySecret,
		"title":        "Login " + nonBodySecret,
		"raw_header":   "HTTP/1.1 200 OK\r\nAuthorization: Bearer " + nonBodySecret + "\r\n",
		"header":       map[string]any{"authorization": "Bearer " + nonBodySecret},
		"request":      "GET / HTTP/1.1\r\nCookie: session=" + nonBodySecret + "\r\n",
		"tech":         []string{nonBodySecret},
		"body_domains": []string{nonBodySecret},
		"chain": []map[string]any{
			{"request": nonBodySecret, "response": "HTTP/1.1 302 Found\r\nSet-Cookie: " + nonBodySecret},
		},
		"knowledgebase": map[string]any{"note": nonBodySecret},
		"body":          "<html>" + secret + "</html>",
	}

	var src Source
	chunks, err := runSource(t, &src, jsonl(t, record))
	require.NoError(t, err)

	scanned := concat(chunks)
	assert.Contains(t, scanned, secret, "the response body should be scanned")
	assert.NotContains(t, scanned, nonBodySecret, "no field other than the body should be scanned")
}

func TestMetadata(t *testing.T) {
	t.Parallel()

	record := map[string]any{
		"timestamp":    "2026-08-28T09:15:00.123456789Z",
		"url":          "https://app.example.com:8443/api/v1/config",
		"final_url":    "https://app.example.com:8443/api/v1/config?redirected=1",
		"input":        "app.example.com",
		"host":         "203.0.113.10",
		"path":         "/api/v1/config",
		"method":       "GET",
		"scheme":       "https",
		"content_type": "application/json",
		"status_code":  200,
		"body":         secret,
	}

	var src Source
	chunks, err := runSource(t, &src, jsonl(t, record))
	require.NoError(t, err)
	require.NotEmpty(t, chunks)

	meta := chunks[0].SourceMetadata.GetHttpx()
	require.NotNil(t, meta)

	assert.Equal(t, "https://app.example.com:8443/api/v1/config", meta.GetUrl())
	assert.Equal(t, "https://app.example.com:8443/api/v1/config?redirected=1", meta.GetFinalUrl())
	assert.Equal(t, "app.example.com", meta.GetInput())
	assert.Equal(t, "203.0.113.10", meta.GetHost())
	assert.Equal(t, "/api/v1/config", meta.GetPath())
	assert.Equal(t, "GET", meta.GetMethod())
	assert.Equal(t, "https", meta.GetScheme())
	assert.Equal(t, "application/json", meta.GetContentType())
	assert.Equal(t, int32(200), meta.GetStatusCode())
	assert.Equal(t, "2026-08-28T09:15:00.123456789Z", meta.GetTimestamp())
	assert.Equal(t, "test.jsonl", meta.GetFile())
	assert.Equal(t, int64(1), meta.GetLine())
	assert.Equal(t, "body", meta.GetBodyField())
	assert.Equal(t, SourceType, chunks[0].SourceType)
}

// TestMetadataURLFallback covers records where httpx omitted `url`.
func TestMetadataURLFallback(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		record   map[string]any
		expected string
	}{
		{
			name:     "falls back to final_url",
			record:   map[string]any{"final_url": "https://example.com/final", "input": "example.com", "body": secret},
			expected: "https://example.com/final",
		},
		{
			name:     "falls back to input",
			record:   map[string]any{"input": "example.com", "body": secret},
			expected: "example.com",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var src Source
			chunks, err := runSource(t, &src, jsonl(t, tc.record))
			require.NoError(t, err)
			require.NotEmpty(t, chunks)
			assert.Equal(t, tc.expected, chunks[0].SourceMetadata.GetHttpx().GetUrl())
		})
	}
}

func TestHeadlessBodyMetadataField(t *testing.T) {
	t.Parallel()

	src := Source{includeHeadlessBody: true}
	chunks, err := runSource(t, &src, jsonl(t, map[string]any{
		"url":           "https://example.com/",
		"headless_body": secret,
	}))
	require.NoError(t, err)
	require.NotEmpty(t, chunks)
	assert.Equal(t, "headless_body", chunks[0].SourceMetadata.GetHttpx().GetBodyField())
}

// TestMalformedRecordsAreSkipped verifies that a single bad line — a truncated
// final record from an interrupted httpx run, or a stray log line — does not
// abort the scan.
func TestMalformedRecordsAreSkipped(t *testing.T) {
	t.Parallel()

	input := jsonl(t, map[string]any{"url": "https://a.example.com/", "body": "A" + secret}) +
		"{\"url\": \"https://truncated.example.com/\", \"body\": \"tru\n" +
		"not json at all\n" +
		"\n" + // blank lines are tolerated
		jsonl(t, map[string]any{"url": "https://b.example.com/", "body": "B" + secret})

	var src Source
	chunks, err := runSource(t, &src, input)
	require.NoError(t, err)

	scanned := concat(chunks)
	assert.Contains(t, scanned, "A"+secret)
	assert.Contains(t, scanned, "B"+secret)
}

// TestFinalRecordWithoutNewline covers files that do not end in a newline.
func TestFinalRecordWithoutNewline(t *testing.T) {
	t.Parallel()

	input := strings.TrimSuffix(jsonl(t, map[string]any{"url": "https://example.com/", "body": secret}), "\n")

	var src Source
	chunks, err := runSource(t, &src, input)
	require.NoError(t, err)
	assert.Contains(t, concat(chunks), secret)
}

func TestCRLFDelimitedRecords(t *testing.T) {
	t.Parallel()

	input := strings.ReplaceAll(jsonl(t,
		map[string]any{"url": "https://a.example.com/", "body": "A" + secret},
		map[string]any{"url": "https://b.example.com/", "body": "B" + secret},
	), "\n", "\r\n")

	var src Source
	chunks, err := runSource(t, &src, input)
	require.NoError(t, err)

	scanned := concat(chunks)
	assert.Contains(t, scanned, "A"+secret)
	assert.Contains(t, scanned, "B"+secret)
}

// TestOversizedRecordIsSkipped verifies the reader resynchronises on the next
// record boundary rather than failing the whole stream, which is what
// bufio.Scanner would do.
func TestOversizedRecordIsSkipped(t *testing.T) {
	t.Parallel()

	huge := jsonl(t, map[string]any{"url": "https://huge.example.com/", "body": makeBody(64 * 1024)})
	small := jsonl(t, map[string]any{"url": "https://small.example.com/", "body": "OK" + secret})

	src := Source{maxRecordBytes: 4096}
	chunks, err := runSource(t, &src, huge+small)
	require.NoError(t, err)

	scanned := concat(chunks)
	assert.Contains(t, scanned, "OK"+secret, "the record after an oversized one should still be scanned")
	require.Len(t, chunks, 1, "the oversized record should not produce chunks")
	assert.Equal(t, "https://small.example.com/", chunks[0].SourceMetadata.GetHttpx().GetUrl())
}

// TestManyRecordsWithConcurrency exercises the worker pool and confirms every
// record is accounted for regardless of completion order.
func TestManyRecordsWithConcurrency(t *testing.T) {
	t.Parallel()

	const count = 500

	records := make([]map[string]any, 0, count)
	for i := 0; i < count; i++ {
		records = append(records, map[string]any{
			"url":         fmt.Sprintf("https://host-%d.example.com/", i),
			"status_code": 200,
			"body":        fmt.Sprintf("token-%d-%s", i, secret),
		})
	}

	src := Source{concurrency: 8}
	chunks, err := runSource(t, &src, jsonl(t, records...))
	require.NoError(t, err)

	urls := make(map[string]struct{}, count)
	for _, c := range chunks {
		urls[c.SourceMetadata.GetHttpx().GetUrl()] = struct{}{}
	}
	assert.Len(t, urls, count, "every record should produce a chunk with its own URL")

	scanned := concat(chunks)
	assert.Contains(t, scanned, fmt.Sprintf("token-%d-%s", 0, secret))
	assert.Contains(t, scanned, fmt.Sprintf("token-%d-%s", count-1, secret))
}

// TestLineNumbersAreRecorded confirms that the metadata line number points back
// at the originating record, which is what makes findings greppable against the
// original JSONL (e.g. `sed -n '42p' responses.jsonl | jq`).
func TestLineNumbersAreRecorded(t *testing.T) {
	t.Parallel()

	input := jsonl(t,
		map[string]any{"url": "https://a.example.com/", "body": nil},
		map[string]any{"url": "https://b.example.com/", "body": secret},
	)

	var src Source
	chunks, err := runSource(t, &src, input)
	require.NoError(t, err)
	require.NotEmpty(t, chunks)
	assert.Equal(t, int64(2), chunks[0].SourceMetadata.GetHttpx().GetLine())
}

func TestGzippedInputIsDecompressed(t *testing.T) {
	t.Parallel()

	plain := jsonl(t, map[string]any{"url": "https://example.com/", "body": secret})

	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	_, err := gz.Write([]byte(plain))
	require.NoError(t, err)
	require.NoError(t, gz.Close())

	reader, closeFn, err := maybeDecompress(bytes.NewReader(compressed.Bytes()))
	require.NoError(t, err)
	defer closeFn()

	out, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Equal(t, plain, string(out))
}

func TestUncompressedInputPassesThrough(t *testing.T) {
	t.Parallel()

	plain := jsonl(t, map[string]any{"url": "https://example.com/", "body": secret})

	reader, closeFn, err := maybeDecompress(strings.NewReader(plain))
	require.NoError(t, err)
	defer closeFn()

	out, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Equal(t, plain, string(out))
}
