package elasticsearch

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest/observer"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/log/logtest"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

// fakeES serves the parts of the Elasticsearch API the source uses, for one index.
// The first point in time request returns a 503, which the client retries.
func fakeES(t *testing.T, index string, docs []map[string]any) *httptest.Server {
	t.Helper()

	var pitCalls, searchCalls atomic.Int32
	write := func(w http.ResponseWriter, body any) {
		_ = json.NewEncoder(w).Encode(body)
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The client refuses responses without this header.
		w.Header().Set("X-Elastic-Product", "Elasticsearch")
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/*":
			write(w, map[string]any{index: map[string]any{}})
		case "/" + index + "/_search":
			write(w, map[string]any{"hits": map[string]any{"total": map[string]any{"value": len(docs)}}})
		case "/" + index + "/_pit":
			if pitCalls.Add(1) == 1 {
				w.WriteHeader(http.StatusServiceUnavailable)
				write(w, map[string]any{"error": map[string]any{"type": "unavailable", "reason": "try again"}})
				return
			}
			write(w, map[string]any{"id": "pit-1"})
		case "/_search":
			hits := []map[string]any{}
			if searchCalls.Add(1) == 1 {
				for i, doc := range docs {
					hits = append(hits, map[string]any{
						"_id":     doc["_id"],
						"_source": doc["_source"],
						"sort":    []any{i},
					})
				}
			}
			write(w, map[string]any{"hits": map[string]any{"hits": hits}})
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestSource_DebugLogging(t *testing.T) {
	const (
		index      = "logs"
		testSecret = "esdebuglogtestsecret"
	)
	docs := []map[string]any{
		{"_id": "doc-1", "_source": map[string]any{"@timestamp": "2024-01-01T00:00:00Z", "message": "token = " + testSecret}},
		{"_id": "doc-2", "_source": map[string]any{"@timestamp": "2024-01-01T00:00:01Z"}},
	}

	runSource := func(t *testing.T, debug bool) []observer.LoggedEntry {
		t.Helper()
		srv := fakeES(t, index, docs)
		defer srv.Close()

		ctx, logs := logtest.SourceContext(debug)
		conn, err := anypb.New(&sourcespb.Elasticsearch{Nodes: []string{srv.URL}})
		require.NoError(t, err)

		s := &Source{}
		require.NoError(t, s.Init(ctx, "test source", 1, 1, false, conn, 1))
		if debug {
			logtest.CheckInitLine(t, logs.All())
		}

		chunksCh := make(chan *sources.Chunk, 10)
		require.NoError(t, s.Chunks(ctx, chunksCh))
		close(chunksCh)

		var ids []string
		for chunk := range chunksCh {
			ids = append(ids, chunk.SourceMetadata.GetElasticsearch().GetDocumentId())
		}
		assert.Equal(t, []string{"doc-1"}, ids, "the document without a message is not scanned")
		return logs.All()
	}

	t.Run("debug on", func(t *testing.T) {
		logtest.CheckSourceLines(t, runSource(t, true), testSecret)
	})

	t.Run("debug off", func(t *testing.T) {
		logtest.CheckNoDebugLines(t, runSource(t, false))
	})
}

func TestMakeElasticSearchRequest_ErrorResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Elastic-Product", "Elasticsearch")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"type":"security_exception","reason":"missing authentication credentials"},"status":401}`))
	}))
	defer srv.Close()

	s := &Source{}
	conn, err := anypb.New(&sourcespb.Elasticsearch{Nodes: []string{srv.URL}})
	require.NoError(t, err)
	require.NoError(t, s.Init(context.Background(), "test source", 1, 1, false, conn, 1))

	// The error body used to be read as a list of index names.
	names, err := fetchIndexNames(context.Background(), s.client, "*")
	assert.Nil(t, names)
	assert.EqualError(t, err, "elasticsearch returned 401 Unauthorized: security_exception: missing authentication credentials")
}

// The transport passes an empty response, not nil, when an attempt got no
// response at all, so a network error must still log as a failed request.
func TestAPILogger_NetworkError(t *testing.T) {
	ctx, logs := logtest.SourceContext(true)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:9200/_search", nil)
	require.NoError(t, err)

	require.NoError(t, apiLogger{}.LogRoundTrip(req, &http.Response{}, errors.New("connection refused"), time.Now(), time.Millisecond))

	failed := logs.FilterMessage("Elasticsearch request failed").All()
	require.Len(t, failed, 1)
	assert.Equal(t, "connection refused", failed[0].ContextMap()["error"])
	assert.Zero(t, logs.FilterMessage("Elasticsearch request").Len())
}
