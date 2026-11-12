package github

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shurcooL/githubv4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

// fakeGraphQL is a /graphql endpoint for repo o/r. answer picks the response
// from the query text and variables. It records every query so tests can check
// how many requests were sent and what they looked like.
type fakeGraphQL struct {
	t      *testing.T
	answer func(query string, vars map[string]any) (status int, body any)

	mu      sync.Mutex
	queries []string
}

func newFakeGraphQL(t *testing.T, answer func(query string, vars map[string]any) (int, any)) (*fakeGraphQL, *githubv4.Client) {
	t.Helper()
	f := &fakeGraphQL{t: t, answer: answer}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, githubv4.NewEnterpriseClient(srv.URL, srv.Client())
}

func (f *fakeGraphQL) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Query     string         `json:"query"`
		Variables map[string]any `json:"variables"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		f.t.Errorf("bad request body: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	f.mu.Lock()
	f.queries = append(f.queries, req.Query)
	tooMany := len(f.queries) > 100
	f.mu.Unlock()
	if tooMany {
		// the scan is looping, stop it instead of hanging the test
		f.t.Errorf("too many requests, last query: %s", req.Query)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	status, body := f.answer(req.Query, req.Variables)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func (f *fakeGraphQL) sent() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.queries...)
}

// resetRateLimitResumeTime clears the shared resume time after a test, so a
// wait set by one test does not slow down the next.
func resetRateLimitResumeTime(t *testing.T) {
	t.Helper()
	reset := func() {
		rateLimitMu.Lock()
		rateLimitResumeTime = time.Time{}
		rateLimitMu.Unlock()
	}
	reset()
	t.Cleanup(reset)
}

func gqlData(data map[string]any) map[string]any {
	data["rateLimit"] = map[string]any{"remaining": 5000, "resetAt": "2030-01-01T00:00:00Z"}
	return map[string]any{"data": data}
}

// gqlConn is a GraphQL connection: a page of nodes plus its pageInfo. An empty
// next means this is the last page.
func gqlConn(next string, nodes ...any) map[string]any {
	if nodes == nil {
		nodes = []any{}
	}
	return map[string]any{
		"nodes":    nodes,
		"pageInfo": map[string]any{"hasNextPage": next != "", "endCursor": next},
	}
}

func gqlComment(link string) map[string]any {
	return map[string]any{
		"body":      "comment " + link,
		"url":       link,
		"author":    map[string]any{"login": "octocat"},
		"createdAt": "2024-01-01T00:00:00Z",
		"updatedAt": "2024-01-01T00:00:00Z",
	}
}

func gqlItem(number int, link string, comments map[string]any) map[string]any {
	item := map[string]any{
		"number":    number,
		"title":     "title",
		"body":      "body",
		"url":       link,
		"author":    map[string]any{"login": "octocat"},
		"createdAt": "2024-01-01T00:00:00Z",
	}
	if comments != nil {
		item["comments"] = comments
	}
	return item
}

const (
	issueLink = "https://github.com/o/r/issues/"
	prLinkGQL = "https://github.com/o/r/pull/"
)

// pagedRepoAnswer serves a repo where every listing has a second page: two
// pages of issues, issue 1 with a second page of comments, two pages of PRs,
// PR 10 with a second page of comments and of review threads, and thread t2
// with two more pages of comments.
func pagedRepoAnswer(t *testing.T) func(string, map[string]any) (int, any) {
	return func(q string, v map[string]any) (int, any) {
		after := func(key string) string { s, _ := v[key].(string); return s }
		switch {
		case strings.Contains(q, "nodes(ids:"):
			assert.ElementsMatch(t, []any{"t1", "t2", "t3"}, v["ids"])
			return 200, gqlData(map[string]any{"nodes": []any{
				map[string]any{"id": "t1", "comments": gqlConn("", gqlComment(prLinkGQL+"10#t1-c1"))},
				map[string]any{"id": "t2", "comments": gqlConn("rc1", gqlComment(prLinkGQL+"10#t2-c1"))},
				map[string]any{"id": "t3", "comments": gqlConn("", gqlComment(prLinkGQL+"11#t3-c1"))},
			}})

		case strings.Contains(q, "node(id:"):
			assert.Equal(t, "t2", v["threadID"])
			switch after("commentsAfter") {
			case "rc1":
				return 200, gqlData(map[string]any{"node": map[string]any{"comments": gqlConn("rc2", gqlComment(prLinkGQL+"10#t2-c2"))}})
			case "rc2":
				return 200, gqlData(map[string]any{"node": map[string]any{"comments": gqlConn("", gqlComment(prLinkGQL+"10#t2-c3"))}})
			}

		case strings.Contains(q, "pullRequest(number:") && strings.Contains(q, "reviewThreads"):
			assert.EqualValues(t, 10, v["number"])
			assert.Equal(t, "tc1", after("threadsAfter"))
			return 200, gqlData(map[string]any{"repository": map[string]any{"pullRequest": map[string]any{
				"reviewThreads": gqlConn("", map[string]any{"id": "t2"}),
			}}})

		case strings.Contains(q, "pullRequests(") && strings.Contains(q, "reviewThreads"):
			if after("after") == "" {
				return 200, gqlData(map[string]any{"repository": map[string]any{"pullRequests": gqlConn("tp2",
					map[string]any{"number": 10, "reviewThreads": gqlConn("tc1", map[string]any{"id": "t1"})},
				)}})
			}
			return 200, gqlData(map[string]any{"repository": map[string]any{"pullRequests": gqlConn("",
				map[string]any{"number": 11, "reviewThreads": gqlConn("", map[string]any{"id": "t3"})},
			)}})

		case strings.Contains(q, "pullRequest(number:"):
			assert.EqualValues(t, 10, v["number"])
			assert.Equal(t, "pc1", after("commentsAfter"))
			return 200, gqlData(map[string]any{"repository": map[string]any{"pullRequest": map[string]any{
				"comments": gqlConn("", gqlComment(prLinkGQL+"10#pc2")),
			}}})

		case strings.Contains(q, "pullRequests("):
			if after("after") == "" {
				return 200, gqlData(map[string]any{"repository": map[string]any{"pullRequests": gqlConn("pp2",
					gqlItem(10, prLinkGQL+"10", gqlConn("pc1", gqlComment(prLinkGQL+"10#pc1"))),
				)}})
			}
			return 200, gqlData(map[string]any{"repository": map[string]any{"pullRequests": gqlConn("",
				gqlItem(11, prLinkGQL+"11", gqlConn("")),
			)}})

		case strings.Contains(q, "issue(number:"):
			assert.EqualValues(t, 1, v["number"])
			assert.Equal(t, "ic1", after("commentsAfter"))
			return 200, gqlData(map[string]any{"repository": map[string]any{"issue": map[string]any{
				"comments": gqlConn("", gqlComment(issueLink+"1#ic2")),
			}}})

		case strings.Contains(q, "issues("):
			if after("issuesAfter") == "" {
				return 200, gqlData(map[string]any{"repository": map[string]any{"issues": gqlConn("ip2",
					gqlItem(1, issueLink+"1", gqlConn("ic1", gqlComment(issueLink+"1#ic1"))),
				)}})
			}
			return 200, gqlData(map[string]any{"repository": map[string]any{"issues": gqlConn("",
				gqlItem(2, issueLink+"2", gqlConn("", gqlComment(issueLink+"2#ic3"))),
			)}})
		}

		t.Errorf("unexpected query %s with variables %v", q, v)
		return 500, map[string]any{}
	}
}

func TestGraphQLScan_FollowsEveryPage(t *testing.T) {
	resetRateLimitResumeTime(t)
	fake, client := newFakeGraphQL(t, pagedRepoAnswer(t))

	s := &Source{includeIssueComments: true, includePRComments: true}
	reporter := &collectingReporter{}
	err := s.processRepoIssueandPRsWithCommentsGraphql(context.Background(), client, testRepo, reporter, nil)
	require.NoError(t, err)
	assert.Empty(t, reporter.errs)

	// every item and comment exactly once, nothing repeated by a stuck cursor
	assert.ElementsMatch(t, []string{
		issueLink + "1", issueLink + "2",
		issueLink + "1#ic1", issueLink + "1#ic2", issueLink + "2#ic3",
		prLinkGQL + "10", prLinkGQL + "11",
		prLinkGQL + "10#pc1", prLinkGQL + "10#pc2",
		prLinkGQL + "10#t1-c1", prLinkGQL + "10#t2-c1", prLinkGQL + "10#t2-c2", prLinkGQL + "10#t2-c3",
		prLinkGQL + "11#t3-c1",
	}, reporter.links)

	// issues 2 + issue comments 1 + PRs 2 + PR comments 1 + thread IDs 2 +
	// more thread IDs 1 + thread batch 1 + thread comments 2
	sent := fake.sent()
	assert.Len(t, sent, 12)

	// GitHub rejects variable types that are not GraphQL types. The library
	// takes the type from the Go value, so a plain int slips in as "int!".
	lowercaseType := regexp.MustCompile(`\$\w+:\[?[a-z]`)
	for _, q := range sent {
		assert.False(t, lowercaseType.MatchString(q), "lowercase variable type in query: %s", q)
	}
}

func TestGraphQLScan_OtherErrorFailsWithoutRetry(t *testing.T) {
	resetRateLimitResumeTime(t)
	fake, client := newFakeGraphQL(t, func(string, map[string]any) (int, any) {
		return 200, map[string]any{"errors": []any{map[string]any{
			"type":    "NOT_FOUND",
			"message": "Could not resolve to a Repository with the name 'o/r'.",
		}}}
	})

	s := &Source{includeIssueComments: true}
	start := time.Now()
	err := s.processIssuesWithComments(context.Background(), client, testRepo, &collectingReporter{}, nil)

	require.ErrorContains(t, err, "Could not resolve to a Repository")
	assert.Len(t, fake.sent(), 1)
	assert.Less(t, time.Since(start), 2*time.Second)
}
