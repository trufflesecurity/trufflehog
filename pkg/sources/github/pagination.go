package github

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/go-github/v67/github"
	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

// GitHub list endpoints don't all paginate the same way, and the differences
// are mostly undocumented:
//
//   - /issues offers cursors (`after`) in its next links and returns a 422
//     ("Pagination with the page parameter is not supported") somewhere
//     between 1,000 and 10,000 items when driven by page number alone.
//   - /issues/comments offers only page numbers and stops at 300 pages: page
//     300 comes back full with no next link, and page 301 returns a 422
//     ("pagination is limited for this resource").
//   - /pulls ignores `after` and copies it into its next link, so a client
//     that sends only a cursor fetches page 1 forever.
//
// The helpers in this file never build page or cursor parameters themselves.
// They follow the Link header's rel="next" URL as-is, which uses cursors
// wherever GitHub provides them and page numbers everywhere else, and they
// treat the ways a walk can end as distinct outcomes rather than assuming a
// short page means "done". Every walk either reaches a confirmed end or
// reports why it couldn't, so a cap can never silently truncate a scan.

// pager carries what every walk needs: the client to send follow-up requests
// with, the page size the walk was started with (used to recognize a full
// final page), the caller's rate-limit handler, which sleeps and returns true
// when a request should be retried, and wait, which sleeps between retries of
// transient failures and returns false if the context ended first. A nil wait
// turns transient retries off. listing names the walk in log lines, for
// example "issue comments"; pager is passed by value, so each walk sets its
// own without affecting the caller's.
type pager struct {
	client  *github.Client
	perPage int
	retry   func(error) bool
	wait    func(context.Context, time.Duration) bool
	listing string
}

// walkOutcome describes how a page walk ended. A walk that isn't capped
// reached a confirmed end: a short final page, or an empty probe page.
type walkOutcome struct {
	capped bool
	items  int
}

// walkError reports a walk that could not finish, with enough context for a
// support engineer to see how far it got. since is zero for walks that don't
// use since windows.
type walkError struct {
	items int
	since time.Time
	err   error
}

func (e *walkError) Error() string {
	if e.since.IsZero() {
		return fmt.Sprintf("walk incomplete after %d items: %v", e.items, e.err)
	}
	return fmt.Sprintf("walk incomplete after %d items (since=%s): %v", e.items, e.since.UTC().Format(time.RFC3339), e.err)
}

func (e *walkError) Unwrap() error { return e.err }

// walkPages fetches the first page with first (a typed go-github call that
// sets the filters and page size), then follows rel="next" links until the
// walk ends. visit receives each page before the next one is requested, so a
// later failure can never discard pages that were already read.
//
// When there is no next link, the walk ends one of three ways:
//   - The final page is short: the walk is complete.
//   - The final page is full and its URL carries a cursor (`after` or
//     `before`): the walk is capped. GitHub goes by the cursor, so asking for
//     the next page number would just return the same page again.
//   - The final page is full and its URL uses page numbers (or none, for the
//     first page): the next page number is probed. An empty page means the
//     results exactly filled the last page, data means the walk continues,
//     and a pagination 422 means the endpoint is capped.
//
// A pagination 422 at any point is reported as capped rather than as an
// error so callers can decide whether they have a way past it.
func walkPages[T any](
	ctx context.Context,
	p pager,
	first func(context.Context) ([]T, *github.Response, error),
	visit func([]T) error,
) (walkOutcome, error) {
	var out walkOutcome

	items, resp, err := fetchWithRetry(ctx, p, func() ([]T, *github.Response, error) { return first(ctx) })
	if err != nil {
		if isPaginationCap(err) {
			out.capped = true
			return out, nil
		}
		return out, err
	}

	current := requestURL(resp)
	fetched := map[string]struct{}{}
	if current != nil {
		fetched[current.String()] = struct{}{}
	}

	for {
		if len(items) > 0 {
			if err := visit(items); err != nil {
				return out, err
			}
			out.items += len(items)
		}

		next := nextLink(resp)
		if next == "" {
			if len(items) < p.perPage {
				return out, nil
			}
			if current == nil || hasCursor(current) {
				out.capped = true
				return out, nil
			}
			next = withNextPage(current)
		}

		nextURL, err := p.followable(next)
		if err != nil {
			return out, err
		}
		if _, ok := fetched[nextURL.String()]; ok {
			return out, fmt.Errorf("pagination did not advance: next link repeats %s", redactQuery(nextURL))
		}
		fetched[nextURL.String()] = struct{}{}

		items, resp, err = fetchWithRetry(ctx, p, func() ([]T, *github.Response, error) {
			return fetchPage[T](ctx, p.client, nextURL.String())
		})
		if err != nil {
			if isPaginationCap(err) {
				out.capped = true
				return out, nil
			}
			return out, err
		}
		current = nextURL
	}
}

// sinceWalk describes a walk over an endpoint that accepts `since` and can
// sort by update time: /issues, /issues/comments, and /pulls/comments.
type sinceWalk[T any] struct {
	// name labels log lines, for example "issue comments", and becomes the
	// pager's listing for the walk.
	name string
	// since is the earliest update time to fetch. Zero fetches everything.
	since time.Time
	// list fetches the first page of a window starting at since. It must sort
	// by update time ascending, and must omit `since` when it is zero.
	list func(ctx context.Context, since time.Time) ([]T, *github.Response, error)
	// key returns an item's ID and last update time.
	key func(T) (int64, time.Time)
	// visit receives each page of items not already seen.
	visit func([]T) error
}

// walkUpdatedSince walks an endpoint in update-time order, and gets past
// GitHub's per-query result caps by starting a new window at the last update
// time seen whenever a window ends capped. `since` is inclusive and each
// window gets a fresh cap, so the walk continues where the previous window
// stopped. Items at the boundary timestamp that were already visited are
// dropped by ID.
//
// Ascending order also keeps the walk complete while the repo changes under
// it: an item updated mid-walk moves to the end, where the walk still reaches
// it, instead of shifting earlier pages.
//
// A window that ends complete finishes the walk, even if it produced nothing
// new; that is what an exact fit on a cursor endpoint looks like. A window
// that ends capped without producing anything new is an error, because more
// items share one timestamp than a window can hold and no later window can
// get past them.
func walkUpdatedSince[T any](ctx context.Context, p pager, w sinceWalk[T]) (int, error) {
	p.listing = w.name
	windowStart := w.since
	var (
		total int
		// latest is the newest update time visited, and atLatest holds the IDs
		// visited at exactly that time. When a window starts at latest, the
		// API returns those items again, and atLatest is how they are dropped.
		latest   time.Time
		atLatest = map[int64]struct{}{}
	)

	for {
		newInWindow := 0
		outcome, err := walkPages(ctx, p,
			func(ctx context.Context) ([]T, *github.Response, error) { return w.list(ctx, windowStart) },
			func(items []T) error {
				fresh := make([]T, 0, len(items))
				for _, item := range items {
					id, updated := w.key(item)
					if updated.Equal(windowStart) {
						if _, seen := atLatest[id]; seen {
							continue
						}
					}
					fresh = append(fresh, item)
					switch {
					case updated.After(latest):
						latest = updated
						atLatest = map[int64]struct{}{id: {}}
					case updated.Equal(latest):
						atLatest[id] = struct{}{}
					}
				}
				if len(fresh) == 0 {
					return nil
				}
				newInWindow += len(fresh)
				total += len(fresh)
				return w.visit(fresh)
			},
		)
		if err != nil {
			return total, &walkError{items: total, since: windowStart, err: err}
		}
		if !outcome.capped {
			return total, nil
		}
		if newInWindow == 0 {
			return total, &walkError{
				items: total,
				since: windowStart,
				err:   fmt.Errorf("listing is capped and a new window made no progress: more items share update time %s than one window can return", windowStart.UTC().Format(time.RFC3339)),
			}
		}

		windowStart = latest
		ctx.Logger().V(2).Info("listing capped, continuing from last update time",
			"listing", w.name, "since", windowStart.UTC().Format(time.RFC3339), "items_so_far", total)
	}
}

// maxTransientRetries bounds how many times one page request is retried after
// a transient failure. With the backoff below, a request gets about a minute
// of retries before the walk reports it as an error.
const maxTransientRetries = 5

// transientBackoff returns how long to wait before the given retry, starting
// at 2 seconds, doubling, and capped at 30 seconds.
func transientBackoff(retry int) time.Duration {
	return min(2*time.Second<<retry, 30*time.Second)
}

// fetchWithRetry runs fetch, retrying in two independent cases. Rate limits
// are retried for as long as the rate-limit handler says to; it sleeps until
// the limit resets and returns false once the context is cancelled. Transient
// failures (see isTransient) are retried up to maxTransientRetries times with
// backoff. Every request here is a GET, so a retry can't repeat a side effect.
//
// Long walks make transient failures likely: a full walk of a large repo's
// review comments takes hours at several seconds per page, and GitHub
// occasionally cancels a slow request outright.
//
// The connectors' HTTP clients (common.RetryableHTTPClientTimeout) already
// retry a failed round trip a few times with short backoff, so this is a
// second layer, not a duplicate. It covers what that layer can't: a response
// whose body fails partway through reading (an HTTP/2 stream reset arrives
// here, from the JSON decoder, after the round trip has succeeded), and a
// failure that outlasts the client's own retries, which surfaces as
// "giving up after N attempt(s)". Each attempt here is bounded by the
// client's 60 second timeout, so a page that keeps failing is reported after
// several minutes rather than retried indefinitely.
func fetchWithRetry[T any](ctx context.Context, p pager, fetch func() ([]T, *github.Response, error)) ([]T, *github.Response, error) {
	transientRetries := 0
	for {
		items, resp, err := fetch()
		if p.retry != nil && p.retry(err) {
			continue
		}
		if err == nil || p.wait == nil || !isTransient(ctx, err) {
			return items, resp, err
		}
		if transientRetries == maxTransientRetries {
			return items, resp, fmt.Errorf("giving up after %d attempts: %w", transientRetries+1, err)
		}
		delay := transientBackoff(transientRetries)
		transientRetries++
		ctx.Logger().V(2).Info("retrying GitHub API request after transient error",
			"listing", p.listing, "retry", transientRetries, "max_retries", maxTransientRetries, "retry_in", delay.String(), "error", err.Error())
		if !p.wait(ctx, delay) {
			return items, resp, err
		}
	}
}

// isTransient reports whether a failed request is worth retrying as-is:
// a 5xx from GitHub, or a transport failure such as a reset connection, a
// timeout, or a response cut off partway. Anything caused by the context
// ending is not transient, and neither is any other API error; rate limits
// have their own handler, and a 4xx (including the pagination 422s) will fail
// the same way again.
func isTransient(ctx context.Context, err error) bool {
	if ctx.Err() != nil {
		return false
	}

	var (
		errResp    *github.ErrorResponse
		rateLimit  *github.RateLimitError
		abuseLimit *github.AbuseRateLimitError
	)
	switch {
	case errors.As(err, &rateLimit), errors.As(err, &abuseLimit):
		return false
	case errors.As(err, &errResp):
		return errResp.Response != nil && errResp.Response.StatusCode >= http.StatusInternalServerError
	}

	var (
		urlErr *url.Error
		netErr net.Error
	)
	if errors.As(err, &urlErr) || errors.As(err, &netErr) ||
		errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, syscall.ECONNRESET) {
		return true
	}
	// A stream reset that arrives while the body is being read surfaces from
	// the JSON decoder as net/http's bundled HTTP/2 stream error. That type
	// is unexported, so its message is the only way to recognize it.
	return strings.Contains(err.Error(), "stream error:")
}

// fetchPage sends a GET for an absolute next-page URL through the go-github
// client, so authentication, rate-limit errors, and error decoding behave
// exactly as they do for the typed list methods.
func fetchPage[T any](ctx context.Context, client *github.Client, rawURL string) ([]T, *github.Response, error) {
	req, err := client.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, nil, err
	}
	var page []T
	resp, err := client.Do(ctx, req, &page)
	return page, resp, err
}

// followable parses a next-page URL and refuses one that points at a host
// other than the API's. The connectors attach credentials in the HTTP
// transport, which would send the token to whatever host the URL names.
func (p pager) followable(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid pagination link: %w", err)
	}
	if !u.IsAbs() {
		u = p.client.BaseURL.ResolveReference(u)
	}
	if !strings.EqualFold(u.Host, p.client.BaseURL.Host) {
		return nil, fmt.Errorf("pagination link points at %q, not the API host %q", u.Host, p.client.BaseURL.Host)
	}
	return u, nil
}

// isPaginationCap reports whether err is one of GitHub's pagination 422s:
// the /issues offset limit ("Pagination with the page parameter is not
// supported for large datasets") or the /issues/comments page cap
// ("pagination is limited for this resource"). Any other 422 is a real
// error.
func isPaginationCap(err error) bool {
	var errResp *github.ErrorResponse
	if !errors.As(err, &errResp) || errResp.Response == nil {
		return false
	}
	return errResp.Response.StatusCode == http.StatusUnprocessableEntity &&
		strings.Contains(strings.ToLower(errResp.Message), "pagination")
}

// linkPattern matches one `<url>; rel="..."` entry of a Link header. Matching
// the angle brackets, instead of splitting on commas, keeps URLs that
// contain commas intact.
var linkPattern = regexp.MustCompile(`<([^>]*)>\s*;\s*rel="([^"]*)"`)

// nextLink returns the rel="next" URL from a response's Link headers, or ""
// when there is none.
func nextLink(resp *github.Response) string {
	if resp == nil || resp.Response == nil {
		return ""
	}
	for _, header := range resp.Header.Values("Link") {
		for _, match := range linkPattern.FindAllStringSubmatch(header, -1) {
			for _, rel := range strings.Fields(match[2]) {
				if rel == "next" {
					return match[1]
				}
			}
		}
	}
	return ""
}

// requestURL returns the URL a response was fetched from, or nil when the
// response doesn't record it.
func requestURL(resp *github.Response) *url.URL {
	if resp == nil || resp.Response == nil || resp.Request == nil || resp.Request.URL == nil {
		return nil
	}
	u := *resp.Request.URL
	return &u
}

// hasCursor reports whether a page URL is positioned by cursor. GitHub's
// /issues links carry both `page` and `after`, and the cursor is what counts.
func hasCursor(u *url.URL) bool {
	q := u.Query()
	return q.Get("after") != "" || q.Get("before") != ""
}

// withNextPage returns u with its page number incremented. A URL without a
// page number is page 1.
func withNextPage(u *url.URL) string {
	q := u.Query()
	page, err := strconv.Atoi(q.Get("page"))
	if err != nil || page < 1 {
		page = 1
	}
	q.Set("page", strconv.Itoa(page+1))
	next := *u
	next.RawQuery = q.Encode()
	return next.String()
}

// redactQuery drops the query string from a URL for error messages, since
// cursors are long and opaque and add nothing for a reader.
func redactQuery(u *url.URL) string {
	redacted := *u
	redacted.RawQuery = ""
	return redacted.String()
}
