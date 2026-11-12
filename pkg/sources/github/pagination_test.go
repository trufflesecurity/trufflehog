package github

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-github/v67/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

// fakeListing serves one GitHub list endpoint with the paging behaviors the
// helpers have to cope with: `since` filtering (inclusive), page numbers or
// cursors in next links, and a page cap that ends with a full page and no
// next link, followed by a pagination 422.
type fakeListing struct {
	mu sync.Mutex
	// records must be sorted by updated, ascending, as the real endpoints
	// return them for sort=updated&direction=asc.
	records []fakeRecord
	// cursor adds `after` to next links, and positions requests by it,
	// the way /issues does.
	cursor bool
	// maxPages caps the listing: the last allowed page has no next link and
	// any later page returns a pagination 422. Zero means no cap.
	maxPages int
	// linkPastCap keeps the next link on the last allowed page, so the 422
	// arrives mid-walk instead of on a probe.
	linkPastCap bool
	// omitNext drops the next link from the given pages even when more
	// records remain.
	omitNext map[int]bool
	// fail, when set, can replace any response. It receives the 1-based
	// request count and the request, and returns true if it wrote a response.
	fail func(n int, w http.ResponseWriter, r *http.Request) bool

	requests []url.Values
}

type fakeRecord struct {
	updated time.Time
	body    map[string]any
}

const paginationCapMessage = "In order to keep the API fast for everyone, pagination is limited for this resource."

func (f *fakeListing) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	q := r.URL.Query()
	f.requests = append(f.requests, q)
	if f.fail != nil && f.fail(len(f.requests), w, r) {
		return
	}

	records := f.records
	if s := q.Get("since"); s != "" {
		since, err := time.Parse(time.RFC3339, s)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": "bad since"})
			return
		}
		filtered := make([]fakeRecord, 0, len(records))
		for _, rec := range records {
			if !rec.updated.Before(since) {
				filtered = append(filtered, rec)
			}
		}
		records = filtered
	}

	perPage := 30
	if v, _ := strconv.Atoi(q.Get("per_page")); v > 0 {
		perPage = v
	}
	page := 1
	if v, _ := strconv.Atoi(q.Get("page")); v > 0 {
		page = v
	}
	if after := q.Get("after"); f.cursor && after != "" {
		page, _ = strconv.Atoi(strings.TrimPrefix(after, "cursor-"))
	}
	if f.maxPages > 0 && page > f.maxPages {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"message": paginationCapMessage})
		return
	}

	start := min((page-1)*perPage, len(records))
	end := min(start+perPage, len(records))
	atCap := f.maxPages > 0 && page == f.maxPages
	if end < len(records) && !f.omitNext[page] && (!atCap || f.linkPastCap) {
		next := url.Values{}
		for k, v := range q {
			next[k] = v
		}
		next.Set("page", strconv.Itoa(page+1))
		if f.cursor {
			next.Set("after", fmt.Sprintf("cursor-%d", page+1))
		}
		w.Header().Set("Link", fmt.Sprintf(`<http://%s%s?%s>; rel="next", <http://%s%s?page=1>; rel="first"`,
			r.Host, r.URL.Path, next.Encode(), r.Host, r.URL.Path))
	}

	body := make([]map[string]any, 0, end-start)
	for _, rec := range records[start:end] {
		body = append(body, rec.body)
	}
	writeJSON(w, http.StatusOK, body)
}

func (f *fakeListing) requestCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
}

func (f *fakeListing) requestedPages() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	pages := make([]string, 0, len(f.requests))
	for _, q := range f.requests {
		page := q.Get("page")
		if page == "" {
			page = "1"
		}
		pages = append(pages, page)
	}
	return pages
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// testItem is the shape the helper tests decode pages into.
type testItem struct {
	ID        int64     `json:"id"`
	UpdatedAt time.Time `json:"updated_at"`
}

var testEpoch = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

// sequentialRecords returns n records with IDs 1..n updated one minute apart.
func sequentialRecords(n int) []fakeRecord {
	updated := make([]time.Time, n)
	for i := range updated {
		updated[i] = testEpoch.Add(time.Duration(i) * time.Minute)
	}
	return recordsAt(updated...)
}

// recordsAt returns one record per timestamp, with IDs 1..n in order.
func recordsAt(updated ...time.Time) []fakeRecord {
	recs := make([]fakeRecord, len(updated))
	for i, t := range updated {
		recs[i] = fakeRecord{updated: t, body: map[string]any{"id": i + 1, "updated_at": t}}
	}
	return recs
}

// newTestPager serves handler at /items and returns a pager for it with a
// page size of 3 and no retries.
func newTestPager(t *testing.T, handler http.Handler) pager {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle("/items", handler)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return pager{client: newTestClient(t, srv), perPage: 3}
}

func newTestClient(t *testing.T, srv *httptest.Server) *github.Client {
	t.Helper()
	client := github.NewClient(srv.Client())
	base, err := url.Parse(srv.URL + "/")
	require.NoError(t, err)
	client.BaseURL = base
	return client
}

// firstItems fetches the first page of /items the way a typed go-github list
// call would, with the pager's page size.
func firstItems(p pager) func(context.Context) ([]testItem, *github.Response, error) {
	return func(ctx context.Context) ([]testItem, *github.Response, error) {
		return fetchPage[testItem](ctx, p.client, fmt.Sprintf("items?per_page=%d", p.perPage))
	}
}

// collect returns a visit func that records item IDs in order.
func collect(ids *[]int64) func([]testItem) error {
	return func(items []testItem) error {
		for _, item := range items {
			*ids = append(*ids, item.ID)
		}
		return nil
	}
}

func idsUpTo(n int) []int64 {
	ids := make([]int64, n)
	for i := range ids {
		ids[i] = int64(i + 1)
	}
	return ids
}

func TestWalkPages_FollowsNextLinksToShortFinalPage(t *testing.T) {
	listing := &fakeListing{records: sequentialRecords(7)}
	p := newTestPager(t, listing)

	var ids []int64
	outcome, err := walkPages(context.Background(), p, firstItems(p), collect(&ids))

	require.NoError(t, err)
	assert.False(t, outcome.capped)
	assert.Equal(t, 7, outcome.items)
	assert.Equal(t, idsUpTo(7), ids)
	assert.Equal(t, []string{"1", "2", "3"}, listing.requestedPages())
}

func TestWalkPages_FullFinalPageWithEmptyProbeIsComplete(t *testing.T) {
	listing := &fakeListing{records: sequentialRecords(6)}
	p := newTestPager(t, listing)

	var ids []int64
	outcome, err := walkPages(context.Background(), p, firstItems(p), collect(&ids))

	require.NoError(t, err)
	assert.False(t, outcome.capped)
	assert.Equal(t, idsUpTo(6), ids)
	assert.Equal(t, []string{"1", "2", "3"}, listing.requestedPages(), "page 3 is the probe")
}

func TestWalkPages_ProbeThatFindsDataKeepsWalking(t *testing.T) {
	listing := &fakeListing{records: sequentialRecords(8), omitNext: map[int]bool{1: true}}
	p := newTestPager(t, listing)

	var ids []int64
	outcome, err := walkPages(context.Background(), p, firstItems(p), collect(&ids))

	require.NoError(t, err)
	assert.False(t, outcome.capped)
	assert.Equal(t, idsUpTo(8), ids)
}

func TestWalkPages_ProbeThatHitsPaginationLimitIsCapped(t *testing.T) {
	listing := &fakeListing{records: sequentialRecords(9), maxPages: 2}
	p := newTestPager(t, listing)

	var ids []int64
	outcome, err := walkPages(context.Background(), p, firstItems(p), collect(&ids))

	require.NoError(t, err)
	assert.True(t, outcome.capped)
	assert.Equal(t, 6, outcome.items)
	assert.Equal(t, idsUpTo(6), ids)
	assert.Equal(t, []string{"1", "2", "3"}, listing.requestedPages())
}

func TestWalkPages_PaginationLimitMidWalkIsCapped(t *testing.T) {
	listing := &fakeListing{records: sequentialRecords(9), maxPages: 2, linkPastCap: true}
	p := newTestPager(t, listing)

	var ids []int64
	outcome, err := walkPages(context.Background(), p, firstItems(p), collect(&ids))

	require.NoError(t, err)
	assert.True(t, outcome.capped)
	assert.Equal(t, idsUpTo(6), ids)
}

func TestWalkPages_PaginationLimitOnFirstPageIsCapped(t *testing.T) {
	listing := &fakeListing{fail: func(_ int, w http.ResponseWriter, _ *http.Request) bool {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{
			"message": "Pagination with the page parameter is not supported for large datasets, please use cursor based pagination (after/before)",
		})
		return true
	}}
	p := newTestPager(t, listing)

	var ids []int64
	outcome, err := walkPages(context.Background(), p, firstItems(p), collect(&ids))

	require.NoError(t, err)
	assert.True(t, outcome.capped)
	assert.Empty(t, ids)
}

func TestWalkPages_FullFinalCursorPageIsCappedWithoutProbe(t *testing.T) {
	// /issues next links carry both page and after; probing page+1 would be
	// ignored in favor of the cursor and return the same page again.
	listing := &fakeListing{records: sequentialRecords(9), cursor: true, maxPages: 2}
	p := newTestPager(t, listing)

	var ids []int64
	outcome, err := walkPages(context.Background(), p, firstItems(p), collect(&ids))

	require.NoError(t, err)
	assert.True(t, outcome.capped)
	assert.Equal(t, idsUpTo(6), ids)
	assert.Equal(t, 2, listing.requestCount(), "no probe after a cursor page")
}

func TestWalkPages_FollowsCursorLinksVerbatim(t *testing.T) {
	listing := &fakeListing{records: sequentialRecords(8), cursor: true}
	p := newTestPager(t, listing)

	var ids []int64
	outcome, err := walkPages(context.Background(), p, firstItems(p), collect(&ids))

	require.NoError(t, err)
	assert.False(t, outcome.capped)
	assert.Equal(t, idsUpTo(8), ids)
	require.Len(t, listing.requests, 3)
	assert.Equal(t, "cursor-3", listing.requests[2].Get("after"))
}

func TestWalkPages_NonPaginationUnprocessableEntityIsAnError(t *testing.T) {
	listing := &fakeListing{
		records: sequentialRecords(9),
		fail: func(n int, w http.ResponseWriter, _ *http.Request) bool {
			if n != 2 {
				return false
			}
			writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"message": "Validation Failed"})
			return true
		},
	}
	p := newTestPager(t, listing)

	var ids []int64
	outcome, err := walkPages(context.Background(), p, firstItems(p), collect(&ids))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "Validation Failed")
	assert.Equal(t, 3, outcome.items)
	assert.Equal(t, idsUpTo(3), ids, "pages read before the error are kept")
}

func TestWalkPages_RejectsNextLinkToAnotherHost(t *testing.T) {
	listing := &fakeListing{fail: func(_ int, w http.ResponseWriter, _ *http.Request) bool {
		w.Header().Set("Link", `<https://attacker.example/items?page=2>; rel="next"`)
		writeJSON(w, http.StatusOK, []map[string]any{{"id": 1}, {"id": 2}, {"id": 3}})
		return true
	}}
	p := newTestPager(t, listing)

	var ids []int64
	_, err := walkPages(context.Background(), p, firstItems(p), collect(&ids))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "attacker.example")
	assert.Equal(t, idsUpTo(3), ids)
	assert.Equal(t, 1, listing.requestCount())
}

func TestWalkPages_ErrorsWhenNextLinkRepeats(t *testing.T) {
	// /pulls echoes an `after` it ignores, so a cursor-only next link would
	// fetch the same page forever.
	listing := &fakeListing{fail: func(_ int, w http.ResponseWriter, r *http.Request) bool {
		w.Header().Set("Link", fmt.Sprintf(`<http://%s/items?per_page=3&after=abc>; rel="next"`, r.Host))
		writeJSON(w, http.StatusOK, []map[string]any{{"id": 1}, {"id": 2}, {"id": 3}})
		return true
	}}
	p := newTestPager(t, listing)

	var ids []int64
	_, err := walkPages(context.Background(), p, firstItems(p), collect(&ids))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "did not advance")
	assert.Equal(t, 2, listing.requestCount())
}

func TestWalkPages_RetriesWhenRateLimitHandlerSaysTo(t *testing.T) {
	listing := &fakeListing{
		records: sequentialRecords(7),
		fail: func(n int, w http.ResponseWriter, _ *http.Request) bool {
			if n != 2 {
				return false
			}
			writeJSON(w, http.StatusForbidden, map[string]string{"message": "slow down"})
			return true
		},
	}
	p := newTestPager(t, listing)
	retries := 0
	p.retry = func(err error) bool {
		if err == nil || retries > 0 {
			return false
		}
		retries++
		return true
	}

	var ids []int64
	outcome, err := walkPages(context.Background(), p, firstItems(p), collect(&ids))

	require.NoError(t, err)
	assert.False(t, outcome.capped)
	assert.Equal(t, 1, retries)
	assert.Equal(t, idsUpTo(7), ids)
	assert.Equal(t, []string{"1", "2", "2", "3"}, listing.requestedPages())
}

// recordWaits turns on transient retries for p and records each requested
// delay instead of sleeping.
func recordWaits(p *pager) *[]time.Duration {
	var waits []time.Duration
	p.wait = func(_ context.Context, d time.Duration) bool {
		waits = append(waits, d)
		return true
	}
	return &waits
}

// failRequest returns a fail func that writes status for the given request
// numbers.
func failRequest(status int, requests ...int) func(int, http.ResponseWriter, *http.Request) bool {
	return func(n int, w http.ResponseWriter, _ *http.Request) bool {
		if !slices.Contains(requests, n) {
			return false
		}
		writeJSON(w, status, map[string]string{"message": http.StatusText(status)})
		return true
	}
}

func TestWalkPages_RetriesTransientServerErrors(t *testing.T) {
	listing := &fakeListing{records: sequentialRecords(7), fail: failRequest(http.StatusBadGateway, 2, 3)}
	p := newTestPager(t, listing)
	waits := recordWaits(&p)

	var ids []int64
	outcome, err := walkPages(context.Background(), p, firstItems(p), collect(&ids))

	require.NoError(t, err)
	assert.False(t, outcome.capped)
	assert.Equal(t, idsUpTo(7), ids)
	assert.Equal(t, []time.Duration{2 * time.Second, 4 * time.Second}, *waits)
	assert.Equal(t, []string{"1", "2", "2", "2", "3"}, listing.requestedPages())
}

func TestWalkPages_RetriesResponseCutOffPartway(t *testing.T) {
	listing := &fakeListing{
		records: sequentialRecords(7),
		fail: func(n int, w http.ResponseWriter, _ *http.Request) bool {
			if n != 2 {
				return false
			}
			// Promise a longer body than is sent, then drop the connection,
			// the way a stream reset mid-response looks to the client.
			conn, buf, err := w.(http.Hijacker).Hijack()
			if err != nil {
				panic(err)
			}
			_, _ = buf.WriteString("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1000\r\n\r\n[{\"id\":4")
			_ = buf.Flush()
			_ = conn.Close()
			return true
		},
	}
	p := newTestPager(t, listing)
	waits := recordWaits(&p)

	var ids []int64
	_, err := walkPages(context.Background(), p, firstItems(p), collect(&ids))

	require.NoError(t, err)
	assert.Equal(t, idsUpTo(7), ids)
	assert.Len(t, *waits, 1)
}

func TestWalkPages_GivesUpAfterBoundedTransientRetries(t *testing.T) {
	listing := &fakeListing{records: sequentialRecords(7), fail: failRequest(http.StatusServiceUnavailable, 2, 3, 4, 5, 6, 7)}
	p := newTestPager(t, listing)
	waits := recordWaits(&p)

	var ids []int64
	outcome, err := walkPages(context.Background(), p, firstItems(p), collect(&ids))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "giving up after 6 attempts")
	assert.Contains(t, err.Error(), "503")
	assert.Equal(t, []time.Duration{2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 30 * time.Second}, *waits)
	assert.Equal(t, 3, outcome.items)
	assert.Equal(t, idsUpTo(3), ids, "pages read before the failure are kept")
}

func TestWalkPages_DoesNotRetryClientErrors(t *testing.T) {
	listing := &fakeListing{records: sequentialRecords(7), fail: failRequest(http.StatusNotFound, 2)}
	p := newTestPager(t, listing)
	waits := recordWaits(&p)

	var ids []int64
	_, err := walkPages(context.Background(), p, firstItems(p), collect(&ids))

	require.Error(t, err)
	assert.NotContains(t, err.Error(), "giving up")
	assert.Empty(t, *waits)
	assert.Equal(t, 2, listing.requestCount())
}

func TestWalkPages_StopsRetryingWhenWaitIsInterrupted(t *testing.T) {
	listing := &fakeListing{records: sequentialRecords(7), fail: failRequest(http.StatusBadGateway, 2, 3)}
	p := newTestPager(t, listing)
	p.wait = func(context.Context, time.Duration) bool { return false }

	var ids []int64
	_, err := walkPages(context.Background(), p, firstItems(p), collect(&ids))

	require.Error(t, err)
	assert.Equal(t, 2, listing.requestCount())
}

func TestIsTransient(t *testing.T) {
	apiErr := func(status int) error {
		return &github.ErrorResponse{Response: &http.Response{StatusCode: status}, Message: http.StatusText(status)}
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	tests := []struct {
		name string
		ctx  context.Context
		err  error
		want bool
	}{
		{name: "server error", err: apiErr(http.StatusBadGateway), want: true},
		{name: "client error", err: apiErr(http.StatusNotFound)},
		{name: "pagination cap", err: apiErr(http.StatusUnprocessableEntity)},
		{name: "primary rate limit", err: &github.RateLimitError{Response: &http.Response{StatusCode: http.StatusForbidden}}},
		{name: "secondary rate limit", err: &github.AbuseRateLimitError{Response: &http.Response{StatusCode: http.StatusForbidden}}},
		{name: "transport failure", err: &url.Error{Op: "Get", URL: "https://api.github.com/x", Err: errors.New("connection reset by peer")}, want: true},
		{name: "body cut off", err: fmt.Errorf("decoding: %w", io.ErrUnexpectedEOF), want: true},
		{name: "http2 stream reset", err: errors.New("stream error: stream ID 261; CANCEL; received from peer"), want: true},
		{name: "context ended", ctx: cancelled, err: apiErr(http.StatusBadGateway)},
		{name: "other error", err: errors.New("invalid pagination link")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := tt.ctx
			if ctx == nil {
				ctx = context.Background()
			}
			assert.Equal(t, tt.want, isTransient(ctx, tt.err))
		})
	}
}

func TestWalkPages_StopsWhenVisitFails(t *testing.T) {
	listing := &fakeListing{records: sequentialRecords(9)}
	p := newTestPager(t, listing)
	visitErr := errors.New("reporter closed")

	_, err := walkPages(context.Background(), p, firstItems(p), func([]testItem) error { return visitErr })

	require.ErrorIs(t, err, visitErr)
	assert.Equal(t, 1, listing.requestCount())
}

// sinceItems lists /items through walkUpdatedSince the way the comment
// phases do: sorted by update time, `since` only when set.
func sinceItems(p pager, ids *[]int64) sinceWalk[testItem] {
	return sinceWalk[testItem]{
		name: "items",
		list: func(ctx context.Context, since time.Time) ([]testItem, *github.Response, error) {
			u := fmt.Sprintf("items?per_page=%d&sort=updated&direction=asc", p.perPage)
			if !since.IsZero() {
				u += "&since=" + url.QueryEscape(since.UTC().Format(time.RFC3339))
			}
			return fetchPage[testItem](ctx, p.client, u)
		},
		key:   func(item testItem) (int64, time.Time) { return item.ID, item.UpdatedAt },
		visit: collect(ids),
	}
}

func TestWalkUpdatedSince_ContinuesPastCapInNewWindows(t *testing.T) {
	listing := &fakeListing{records: sequentialRecords(20), maxPages: 2}
	p := newTestPager(t, listing)

	var ids []int64
	total, err := walkUpdatedSince(context.Background(), p, sinceItems(p, &ids))

	require.NoError(t, err)
	assert.Equal(t, 20, total)
	assert.Equal(t, idsUpTo(20), ids, "every item exactly once, in order")
}

func TestWalkUpdatedSince_DropsItemsAlreadySeenAtWindowBoundary(t *testing.T) {
	// Items 5-8 share a timestamp that straddles the first window's cap, so
	// the second window starts at that timestamp and gets items 5 and 6
	// again before the new ones.
	shared := testEpoch.Add(time.Hour)
	listing := &fakeListing{
		records: recordsAt(
			testEpoch, testEpoch.Add(time.Minute), testEpoch.Add(2*time.Minute), testEpoch.Add(3*time.Minute),
			shared, shared, shared, shared,
			shared.Add(time.Minute), shared.Add(2*time.Minute),
		),
		maxPages: 2,
	}
	p := newTestPager(t, listing)

	var ids []int64
	total, err := walkUpdatedSince(context.Background(), p, sinceItems(p, &ids))

	require.NoError(t, err)
	assert.Equal(t, 10, total)
	assert.Equal(t, idsUpTo(10), ids)
}

func TestWalkUpdatedSince_CompleteWindowOfDuplicatesFinishes(t *testing.T) {
	// The first window exactly fills its cap on a cursor endpoint, so it ends
	// capped without a probe. The next window holds only the last item seen,
	// which is the confirmed end of the listing.
	listing := &fakeListing{records: sequentialRecords(6), cursor: true, maxPages: 2}
	p := newTestPager(t, listing)

	var ids []int64
	total, err := walkUpdatedSince(context.Background(), p, sinceItems(p, &ids))

	require.NoError(t, err)
	assert.Equal(t, 6, total)
	assert.Equal(t, idsUpTo(6), ids)
}

func TestWalkUpdatedSince_CappedWindowWithoutProgressIsAnError(t *testing.T) {
	shared := testEpoch.Add(time.Hour)
	listing := &fakeListing{records: recordsAt(shared, shared, shared, shared, shared, shared, shared, shared), maxPages: 2}
	p := newTestPager(t, listing)

	var ids []int64
	total, err := walkUpdatedSince(context.Background(), p, sinceItems(p, &ids))

	require.Error(t, err)
	var walkErr *walkError
	require.ErrorAs(t, err, &walkErr)
	assert.Equal(t, shared, walkErr.since)
	assert.Equal(t, 6, walkErr.items)
	assert.Contains(t, err.Error(), "walk incomplete after 6 items (since=2024-01-01T01:00:00Z)")
	assert.Equal(t, 6, total)
	assert.Equal(t, idsUpTo(6), ids, "items read before the error are kept")
}

func TestWalkUpdatedSince_ReportsWindowStartOnError(t *testing.T) {
	listing := &fakeListing{
		records:  sequentialRecords(20),
		maxPages: 2,
		fail: func(n int, w http.ResponseWriter, _ *http.Request) bool {
			if n != 4 {
				return false
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"message": "boom"})
			return true
		},
	}
	p := newTestPager(t, listing)

	var ids []int64
	_, err := walkUpdatedSince(context.Background(), p, sinceItems(p, &ids))

	require.Error(t, err)
	var walkErr *walkError
	require.ErrorAs(t, err, &walkErr)
	assert.Equal(t, testEpoch.Add(5*time.Minute), walkErr.since, "second window starts at item 6")
	assert.Equal(t, 6, walkErr.items)
}

func TestNextLink(t *testing.T) {
	tests := []struct {
		name   string
		header []string
		want   string
	}{
		{name: "no header"},
		{
			name:   "next among other rels",
			header: []string{`<https://api.github.com/x?page=1>; rel="prev", <https://api.github.com/x?page=3>; rel="next"`},
			want:   "https://api.github.com/x?page=3",
		},
		{
			name:   "url containing a comma",
			header: []string{`<https://api.github.com/x?labels=a,b&page=2>; rel="next"`},
			want:   "https://api.github.com/x?labels=a,b&page=2",
		},
		{
			name:   "next in a second header",
			header: []string{`<https://api.github.com/x?page=1>; rel="first"`, `<https://api.github.com/x?page=2>; rel="next"`},
			want:   "https://api.github.com/x?page=2",
		},
		{
			name:   "no next",
			header: []string{`<https://api.github.com/x?page=1>; rel="first"`},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := http.Header{}
			for _, v := range tt.header {
				h.Add("Link", v)
			}
			resp := &github.Response{Response: &http.Response{Header: h}}
			assert.Equal(t, tt.want, nextLink(resp))
		})
	}
}

func TestFollowableResolvesRelativeLinksAgainstAPIHost(t *testing.T) {
	client := github.NewClient(nil)
	base, err := url.Parse("https://ghe.example.com/api/v3/")
	require.NoError(t, err)
	client.BaseURL = base
	p := pager{client: client}

	u, err := p.followable("/api/v3/repos/o/r/issues?page=2")
	require.NoError(t, err)
	assert.Equal(t, "https://ghe.example.com/api/v3/repos/o/r/issues?page=2", u.String())

	u, err = p.followable("https://GHE.example.com/api/v3/repos/o/r/issues?page=3")
	require.NoError(t, err)
	assert.Equal(t, "GHE.example.com", u.Host)

	_, err = p.followable("https://other.example.com/api/v3/repos/o/r/issues?page=3")
	assert.Error(t, err)
}

func TestWithNextPage(t *testing.T) {
	tests := map[string]string{
		"https://api.github.com/x?per_page=100":        "https://api.github.com/x?page=2&per_page=100",
		"https://api.github.com/x?page=7&per_page=100": "https://api.github.com/x?page=8&per_page=100",
	}
	for in, want := range tests {
		u, err := url.Parse(in)
		require.NoError(t, err)
		assert.Equal(t, want, withNextPage(u))
	}
}

func TestIsPaginationCap(t *testing.T) {
	errFor := func(status int, msg string) error {
		return &github.ErrorResponse{Response: &http.Response{StatusCode: status}, Message: msg}
	}
	assert.True(t, isPaginationCap(errFor(http.StatusUnprocessableEntity, paginationCapMessage)))
	assert.True(t, isPaginationCap(fmt.Errorf("wrapped: %w", errFor(http.StatusUnprocessableEntity, "Pagination with the page parameter is not supported"))))
	assert.False(t, isPaginationCap(errFor(http.StatusUnprocessableEntity, "Validation Failed")))
	assert.False(t, isPaginationCap(errFor(http.StatusForbidden, paginationCapMessage)))
	assert.False(t, isPaginationCap(errors.New("pagination")))
}
