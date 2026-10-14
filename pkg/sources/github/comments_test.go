package github

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-github/v67/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/log"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

// fakeGitHub serves the REST endpoints the comment scan reads for repo o/r
// and gist g1, each backed by its own fakeListing.
type fakeGitHub struct {
	issues        *fakeListing
	issueComments *fakeListing
	pulls         *fakeListing
	prComments    *fakeListing
	gistComments  *fakeListing
	client        *github.Client
}

func newFakeGitHub(t *testing.T) *fakeGitHub {
	t.Helper()
	gh := &fakeGitHub{
		issues:        &fakeListing{},
		issueComments: &fakeListing{},
		pulls:         &fakeListing{},
		prComments:    &fakeListing{},
		gistComments:  &fakeListing{},
	}
	mux := http.NewServeMux()
	mux.Handle("/repos/o/r/issues", gh.issues)
	mux.Handle("/repos/o/r/issues/comments", gh.issueComments)
	mux.Handle("/repos/o/r/pulls", gh.pulls)
	mux.Handle("/repos/o/r/pulls/comments", gh.prComments)
	mux.Handle("/gists/g1/comments", gh.gistComments)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	gh.client = newTestClient(t, srv)
	return gh
}

var testRepo = repoInfo{owner: "o", name: "r", fullName: "o/r"}

// collectingReporter records the link of every chunk the scan emits.
type collectingReporter struct {
	mu    sync.Mutex
	links []string
}

func (r *collectingReporter) ChunkOk(_ context.Context, chunk sources.Chunk) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.links = append(r.links, chunk.SourceMetadata.GetGithub().GetLink())
	return nil
}

func (r *collectingReporter) ChunkErr(context.Context, error) error { return nil }

func issueRecord(number int, updated time.Time) fakeRecord {
	return fakeRecord{updated: updated, body: map[string]any{
		"id": number, "number": number, "updated_at": updated, "created_at": updated,
		"html_url": fmt.Sprintf("https://github.com/o/r/issues/%d", number),
		"title":    "issue", "body": "body",
	}}
}

// prIssueRecord is a pull request as /issues returns it.
func prIssueRecord(number int, updated time.Time) fakeRecord {
	return fakeRecord{updated: updated, body: map[string]any{
		"id": number, "number": number, "updated_at": updated, "created_at": updated,
		"html_url": prLink(number),
		"title":    "pr", "body": "body",
		"pull_request": map[string]any{"url": fmt.Sprintf("https://api.github.com/repos/o/r/pulls/%d", number)},
	}}
}

func prRecord(number int, updated time.Time) fakeRecord {
	return fakeRecord{updated: updated, body: map[string]any{
		"id": number, "number": number, "updated_at": updated, "created_at": updated,
		"html_url": prLink(number), "title": "pr", "body": "body",
	}}
}

func prLink(number int) string { return fmt.Sprintf("https://github.com/o/r/pull/%d", number) }

func commentRecord(id int, updated time.Time, htmlURL string) fakeRecord {
	return fakeRecord{updated: updated, body: map[string]any{
		"id": id, "updated_at": updated, "created_at": updated, "html_url": htmlURL, "body": "comment",
	}}
}

// seedRepo gives o/r one issue, one pull request, a discussion comment on
// each, and a review comment on the pull request.
func seedRepo(gh *fakeGitHub) {
	gh.issues.records = []fakeRecord{issueRecord(1, testEpoch), prIssueRecord(2, testEpoch.Add(time.Minute))}
	gh.pulls.records = []fakeRecord{prRecord(2, testEpoch.Add(time.Minute))}
	gh.issueComments.records = []fakeRecord{
		commentRecord(100, testEpoch.Add(2*time.Minute), "https://github.com/o/r/issues/1#issuecomment-100"),
		commentRecord(101, testEpoch.Add(3*time.Minute), "https://github.com/o/r/pull/2#issuecomment-101"),
	}
	gh.prComments.records = []fakeRecord{
		commentRecord(200, testEpoch.Add(4*time.Minute), "https://github.com/o/r/pull/2#discussion_r200"),
	}
}

func scanComments(t *testing.T, s *Source, gh *fakeGitHub, cutoff *time.Time) (*collectingReporter, error) {
	t.Helper()
	reporter := &collectingReporter{}
	err := s.processIssueandPRsWithCommentsREST(context.Background(), gh.client, testRepo, reporter, cutoff)
	return reporter, err
}

func TestCommentScan_FlagCombinations(t *testing.T) {
	tests := []struct {
		name          string
		issueComments bool
		prComments    bool
		wantLinks     []string
		// unlisted names the endpoints the scan must not request.
		unlisted []string
	}{
		{
			name:          "issue comments only",
			issueComments: true,
			wantLinks: []string{
				"https://github.com/o/r/issues/1",
				"https://github.com/o/r/issues/1#issuecomment-100",
				"https://github.com/o/r/pull/2#issuecomment-101",
			},
			unlisted: []string{"pulls", "pull comments"},
		},
		{
			name:       "pull request comments only",
			prComments: true,
			wantLinks: []string{
				prLink(2),
				"https://github.com/o/r/pull/2#discussion_r200",
			},
			unlisted: []string{"issues", "issue comments"},
		},
		{
			name:          "both",
			issueComments: true,
			prComments:    true,
			wantLinks: []string{
				"https://github.com/o/r/issues/1",
				prLink(2),
				"https://github.com/o/r/issues/1#issuecomment-100",
				"https://github.com/o/r/pull/2#issuecomment-101",
				"https://github.com/o/r/pull/2#discussion_r200",
			},
			unlisted: []string{"pulls"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gh := newFakeGitHub(t)
			seedRepo(gh)
			s := &Source{includeIssueComments: tt.issueComments, includePRComments: tt.prComments}

			reporter, err := scanComments(t, s, gh, nil)

			require.NoError(t, err)
			assert.ElementsMatch(t, tt.wantLinks, reporter.links)
			endpoints := map[string]*fakeListing{
				"issues": gh.issues, "issue comments": gh.issueComments,
				"pulls": gh.pulls, "pull comments": gh.prComments,
			}
			for _, name := range tt.unlisted {
				assert.Zero(t, endpoints[name].requestCount(), "%s should not be listed", name)
			}
		})
	}
}

func TestCommentScan_RequestsSortedListingsWithServerSideCutoff(t *testing.T) {
	gh := newFakeGitHub(t)
	seedRepo(gh)
	s := &Source{includeIssueComments: true, includePRComments: true}
	cutoff := testEpoch.Add(-time.Hour)

	_, err := scanComments(t, s, gh, &cutoff)
	require.NoError(t, err)

	issues := gh.issues.requests[0]
	assert.Equal(t, "all", issues.Get("state"))
	assert.Equal(t, "updated", issues.Get("sort"))
	assert.Equal(t, "asc", issues.Get("direction"))
	assert.Equal(t, "100", issues.Get("per_page"))
	assert.Empty(t, issues.Get("since"), "issue and PR bodies are scanned regardless of the comments timeframe")

	for name, listing := range map[string]*fakeListing{"issue comments": gh.issueComments, "pull comments": gh.prComments} {
		q := listing.requests[0]
		assert.Equal(t, "updated", q.Get("sort"), name)
		assert.Equal(t, "asc", q.Get("direction"), name)
		assert.Equal(t, cutoff.Format(time.RFC3339), q.Get("since"), name)
	}
}

func TestCommentScan_OmitsSinceWithoutCutoff(t *testing.T) {
	gh := newFakeGitHub(t)
	seedRepo(gh)
	s := &Source{includeIssueComments: true, includePRComments: true}

	_, err := scanComments(t, s, gh, nil)
	require.NoError(t, err)

	assert.False(t, gh.issueComments.requests[0].Has("since"))
	assert.False(t, gh.prComments.requests[0].Has("since"))
}

func TestCommentScan_PullsListOnlyConfigListsPullsWithAllStates(t *testing.T) {
	gh := newFakeGitHub(t)
	seedRepo(gh)
	s := &Source{includePRComments: true}

	_, err := scanComments(t, s, gh, nil)
	require.NoError(t, err)

	q := gh.pulls.requests[0]
	assert.Equal(t, "all", q.Get("state"))
	assert.Equal(t, "updated", q.Get("sort"))
	assert.Equal(t, "asc", q.Get("direction"))
}

func TestCommentScan_IssueCommentsContinuePastPageCap(t *testing.T) {
	gh := newFakeGitHub(t)
	for i := range 250 {
		gh.issueComments.records = append(gh.issueComments.records,
			commentRecord(i+1, testEpoch.Add(time.Duration(i)*time.Minute), fmt.Sprintf("https://github.com/o/r/issues/1#issuecomment-%d", i+1)))
	}
	gh.issueComments.maxPages = 1
	s := &Source{includeIssueComments: true}

	reporter, err := scanComments(t, s, gh, nil)

	require.NoError(t, err)
	require.Len(t, reporter.links, 250)
	seen := map[string]bool{}
	for _, link := range reporter.links {
		assert.False(t, seen[link], "comment emitted twice: %s", link)
		seen[link] = true
	}
}

func TestCommentScan_PullsCappedFallsBackToIssueListing(t *testing.T) {
	gh := newFakeGitHub(t)
	const prs = 150
	for n := 1; n <= prs; n++ {
		updated := testEpoch.Add(time.Duration(n) * time.Minute)
		gh.pulls.records = append(gh.pulls.records, prRecord(n, updated))
		gh.issues.records = append(gh.issues.records, prIssueRecord(n, updated))
		if n%10 == 0 {
			gh.issues.records = append(gh.issues.records, issueRecord(1000+n, updated))
		}
	}
	gh.pulls.maxPages = 1
	s := &Source{includePRComments: true}

	reporter, err := scanComments(t, s, gh, nil)

	require.NoError(t, err)
	want := make([]string, 0, prs)
	for n := 1; n <= prs; n++ {
		want = append(want, prLink(n))
	}
	assert.ElementsMatch(t, want, reporter.links, "every PR body exactly once, and no issue bodies")
}

func TestCommentScan_FailedPhaseDoesNotStopTheOthers(t *testing.T) {
	gh := newFakeGitHub(t)
	seedRepo(gh)
	gh.issueComments.fail = func(_ int, w http.ResponseWriter, _ *http.Request) bool {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"message": "Server Error"})
		return true
	}
	var retries int
	s := &Source{
		includeIssueComments: true,
		includePRComments:    true,
		commentRetryWait:     func(context.Context, time.Duration) bool { retries++; return true },
	}
	cutoff := testEpoch.Add(-time.Hour)

	reporter, err := scanComments(t, s, gh, &cutoff)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "issue comments: walk incomplete after 0 items (since=2023-12-31T23:00:00Z): giving up after 6 attempts")
	assert.Contains(t, err.Error(), "Server Error")
	assert.Equal(t, maxTransientRetries, retries)
	assert.NotContains(t, err.Error(), "pull request comments:")
	var walkErr *walkError
	assert.ErrorAs(t, err, &walkErr)
	assert.ElementsMatch(t, []string{
		"https://github.com/o/r/issues/1",
		prLink(2),
		"https://github.com/o/r/pull/2#discussion_r200",
	}, reporter.links)
}

func TestCommentScan_RetryLogNamesTheListing(t *testing.T) {
	gh := newFakeGitHub(t)
	seedRepo(gh)
	gh.issueComments.fail = failRequest(http.StatusBadGateway, 1)
	gh.prComments.fail = failRequest(http.StatusBadGateway, 1)
	s := &Source{
		includeIssueComments: true,
		includePRComments:    true,
		commentRetryWait:     func(context.Context, time.Duration) bool { return true },
	}
	var logs bytes.Buffer
	logger, _ := log.New("test", log.WithJSONSink(&logs, log.WithLevel(2)))
	ctx := context.WithLogger(context.Background(), logger)

	err := s.processIssueandPRsWithCommentsREST(ctx, gh.client, testRepo, &collectingReporter{}, nil)
	require.NoError(t, err)

	var listings []string
	for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		var entry map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &entry))
		if entry["msg"] == "retrying GitHub API request after transient error" {
			listings = append(listings, fmt.Sprint(entry["listing"]))
		}
	}
	assert.Equal(t, []string{"issue comments", "pull request comments"}, listings)
}

func TestProcessGistComments_CappedListingIsAnError(t *testing.T) {
	gh := newFakeGitHub(t)
	for i := range 150 {
		gh.gistComments.records = append(gh.gistComments.records, commentRecord(i+1, testEpoch, ""))
	}
	gh.gistComments.maxPages = 1
	s := &Source{includeGistComments: true}
	reporter := &collectingReporter{}

	err := s.processGistComments(context.Background(), gh.client, "https://gist.github.com/u/g1",
		[]string{"gist.github.com", "u", "g1"}, repoInfo{}, reporter, nil)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "gist comments: walk incomplete after 100 items")
	assert.Contains(t, err.Error(), "no since filter")
	assert.Len(t, reporter.links, 100, "comments read before the cap are kept")
}

func TestProcessGistComments_SkipsOldCommentsAndKeepsGoing(t *testing.T) {
	gh := newFakeGitHub(t)
	for i := range 5 {
		created := testEpoch.Add(time.Duration(i) * time.Hour)
		gh.gistComments.records = append(gh.gistComments.records, fakeRecord{updated: created, body: map[string]any{
			"id": i + 1, "created_at": created, "url": fmt.Sprintf("https://api.github.com/gists/g1/comments/%d", i+1),
		}})
	}
	s := &Source{includeGistComments: true}
	reporter := &collectingReporter{}
	cutoff := testEpoch.Add(150 * time.Minute)

	err := s.processGistComments(context.Background(), gh.client, "https://gist.github.com/u/g1",
		[]string{"gist.github.com", "u", "g1"}, repoInfo{}, reporter, &cutoff)

	require.NoError(t, err)
	assert.Equal(t, []string{
		"https://api.github.com/gists/g1/comments/4",
		"https://api.github.com/gists/g1/comments/5",
	}, reporter.links)
}
