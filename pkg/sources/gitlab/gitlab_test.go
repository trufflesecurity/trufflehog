package gitlab

import (
	stdctx "context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/go-logr/zapr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/log/logtest"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/git"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sourcestest"
)

func Test_setProgressCompleteWithRepo_resumeInfo(t *testing.T) {
	tests := []struct {
		startingResumeInfoSlice []string
		repoURL                 string
		wantResumeInfoSlice     []string
	}{
		{
			startingResumeInfoSlice: []string{},
			repoURL:                 "a",
			wantResumeInfoSlice:     []string{"a"},
		},
		{
			startingResumeInfoSlice: []string{"b"},
			repoURL:                 "a",
			wantResumeInfoSlice:     []string{"a", "b"},
		},
	}

	s := &Source{repos: []string{}}

	for _, tt := range tests {
		s.resumeInfoSlice = tt.startingResumeInfoSlice
		s.setProgressCompleteWithRepo(0, 0, tt.repoURL)
		if !reflect.DeepEqual(s.resumeInfoSlice, tt.wantResumeInfoSlice) {
			t.Errorf("s.setProgressCompleteWithRepo() got: %v, want: %v", s.resumeInfoSlice, tt.wantResumeInfoSlice)
		}
	}
}

func Test_setProgressCompleteWithRepo_Progress(t *testing.T) {
	repos := []string{"a", "b", "c", "d", "e"}
	tests := map[string]struct {
		repos                 []string
		index                 int
		offset                int
		wantPercentComplete   int64
		wantSectionsCompleted int32
		wantSectionsRemaining int32
	}{
		"starting from the beginning, no offset": {
			repos:                 repos,
			index:                 0,
			offset:                0,
			wantPercentComplete:   0,
			wantSectionsCompleted: 0,
			wantSectionsRemaining: 5,
		},
		"resume from the third, offset 2": {
			repos:                 repos[2:],
			index:                 0,
			offset:                2,
			wantPercentComplete:   40,
			wantSectionsCompleted: 2,
			wantSectionsRemaining: 5,
		},
		"resume from the third, on last repo, offset 2": {
			repos:                 repos[2:],
			index:                 2,
			offset:                2,
			wantPercentComplete:   80,
			wantSectionsCompleted: 4,
			wantSectionsRemaining: 5,
		},
	}

	for _, tt := range tests {
		s := &Source{
			repos: tt.repos,
		}

		s.setProgressCompleteWithRepo(tt.index, tt.offset, "")
		gotProgress := s.GetProgress()
		if gotProgress.PercentComplete != tt.wantPercentComplete {
			t.Errorf("s.setProgressCompleteWithRepo() PercentComplete got: %v want: %v", gotProgress.PercentComplete, tt.wantPercentComplete)
		}
		if gotProgress.SectionsCompleted != tt.wantSectionsCompleted {
			t.Errorf("s.setProgressCompleteWithRepo() PercentComplete got: %v want: %v", gotProgress.SectionsCompleted, tt.wantSectionsCompleted)
		}
		if gotProgress.SectionsRemaining != tt.wantSectionsRemaining {
			t.Errorf("s.setProgressCompleteWithRepo() PercentComplete got: %v want: %v", gotProgress.SectionsRemaining, tt.wantSectionsRemaining)
		}
	}
}

func Test_scanRepos_SetProgressComplete(t *testing.T) {
	testCases := []struct {
		name         string
		repos        []string
		wantComplete bool
		wantErr      bool
	}{
		{
			name:         "no repos",
			wantComplete: true,
		},
		{
			name:         "one valid repo",
			repos:        []string{"repo"},
			wantComplete: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			src := &Source{
				repos: tc.repos,
			}
			src.jobPool = &errgroup.Group{}
			src.scanOptions = &git.ScanOptions{}

			_ = src.scanRepos(context.Background(), nil)
			if !tc.wantErr {
				assert.Equal(t, "", src.GetProgress().EncodedResumeInfo)
			}

			gotComplete := src.GetProgress().PercentComplete == 100
			if gotComplete != tc.wantComplete {
				t.Errorf("got: %v, want: %v", gotComplete, tc.wantComplete)
			}
		})
	}
}

func Test_normalizeGitlabEndpoint(t *testing.T) {
	testCases := map[string]struct {
		inputEndpoint  string
		outputEndpoint string
		wantErr        bool
	}{
		"the cloud url should return the cloud url": {
			inputEndpoint:  gitlabCloudBaseURL,
			outputEndpoint: gitlabCloudBaseURL,
		},
		"empty string should return the cloud url": {
			inputEndpoint:  "",
			outputEndpoint: gitlabCloudBaseURL,
		},
		"no scheme cloud url should return the cloud url": {
			inputEndpoint:  "gitlab.com",
			outputEndpoint: gitlabCloudBaseURL,
		},
		"no scheme cloud url with trailing slash should return the cloud url": {
			inputEndpoint:  "gitlab.com/",
			outputEndpoint: gitlabCloudBaseURL,
		},
		"http scheme cloud url with organization should return the cloud url": {
			inputEndpoint:  "http://gitlab.com/trufflesec",
			outputEndpoint: gitlabCloudBaseURL,
		},
		// On-prem endpoint testing.
		"on-prem url should be unchanged": {
			inputEndpoint:  "https://gitlab.trufflesec.com/",
			outputEndpoint: "https://gitlab.trufflesec.com/",
		},
		"on-prem url without trailing slash should have trailing slash added": {
			inputEndpoint:  "https://gitlab.trufflesec.com",
			outputEndpoint: "https://gitlab.trufflesec.com/",
		},
		"on-prem url with http scheme should return an error": {
			inputEndpoint: "http://gitlab.trufflesec.com/",
			wantErr:       true,
		},
		"on-prem with gitlab.com should not rewrite to the cloud url": {
			inputEndpoint:  "https://gitlab.com.trufflesec.com/",
			outputEndpoint: "https://gitlab.com.trufflesec.com/",
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			output, err := normalizeGitlabEndpoint(tc.inputEndpoint)
			assert.Equal(t, tc.outputEndpoint, output)
			assert.Equal(t, tc.wantErr, err != nil)
		})
	}
}

func TestSource_DebugLogging(t *testing.T) {
	const testToken = "glpat-debuglogtestsecret"

	// fakeGitLab serves two pages of group projects. The first request for
	// page 1 fails with a 503, so the client retries it.
	newFakeGitLab := func(t *testing.T) *httptest.Server {
		var failed atomic.Bool
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/v4/groups/1/projects" {
				http.NotFound(w, r)
				return
			}
			if !failed.Swap(true) {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			project := func(id int, path string) map[string]any {
				return map[string]any{
					"id":                  id,
					"name_with_namespace": path,
					"path_with_namespace": path,
					"http_url_to_repo":    "https://gitlab.example.com/" + path + ".git",
				}
			}
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Query().Get("page") == "2" {
				_ = json.NewEncoder(w).Encode([]any{project(3, "org/third")})
				return
			}
			w.Header().Set("X-Next-Page", "2")
			_ = json.NewEncoder(w).Encode([]any{project(1, "org/first"), project(2, "org/ignored")})
		}))
		t.Cleanup(srv.Close)
		return srv
	}

	runSource := func(t *testing.T, ctx context.Context) sourcestest.TestReporter {
		srv := newFakeGitLab(t)
		conn, err := anypb.New(&sourcespb.GitLab{
			Credential:  &sourcespb.GitLab_Token{Token: testToken},
			Endpoint:    "https://gitlab.example.com",
			GroupIds:    []string{"1"},
			IgnoreRepos: []string{"*ignored*"},
		})
		require.NoError(t, err)

		s := Source{}
		require.NoError(t, s.Init(ctx, "test debug logging", 1, 1, false, conn, 1))
		// Init only accepts https, so point the client at the fake server afterwards.
		s.url = srv.URL + "/"

		reporter := sourcestest.TestReporter{}
		require.NoError(t, s.Enumerate(ctx, &reporter))
		require.Empty(t, reporter.UnitErrs)
		require.Len(t, reporter.Units, 2)

		// an ignored unit returns before cloning
		ignored := git.SourceUnit{Kind: git.UnitRepo, ID: "https://gitlab.example.com/org/ignored.git"}
		require.NoError(t, s.ChunkUnit(ctx, ignored, &reporter))
		return reporter
	}

	t.Run("debug on", func(t *testing.T) {
		ctx, logs := logtest.DebugContext()
		ctx = context.WithValues(ctx, "source_name", "test debug logging", "job_id", 1)
		runSource(t, ctx)

		// lines from each level show up
		for _, msg := range []string{
			"GitLab source initialized",                      // V(1)
			"starting group projects enumeration",            // V(1)
			"processing group",                               // V(2)
			"accepting project",                              // V(3)
			"listed group projects",                          // V(4)
			"skipping project",                               // V(4)
			"GitLab API request failed",                      // V(4)
			"Retrying GitLab API request",                    // V(4)
			"cache set: added project metadata in the cache", // V(5)
		} {
			assert.NotZero(t, logs.FilterMessage(msg).Len(), "missing log line %q", msg)
		}

		// both pages were logged, with their group
		pages := logs.FilterMessage("listed group projects").All()
		require.Len(t, pages, 2)
		for i, entry := range pages {
			assert.EqualValues(t, i+1, entry.ContextMap()["page"])
			assert.Equal(t, "1", entry.ContextMap()["group_id"])
		}

		// the failed request says what failed
		failed := logs.FilterMessage("GitLab API request failed").All()
		require.Len(t, failed, 1)
		assert.EqualValues(t, http.StatusServiceUnavailable, failed[0].ContextMap()["status"])
		assert.Equal(t, "/api/v4/groups/1/projects", failed[0].ContextMap()["path"])

		// both skips (in enumeration and in ChunkUnit) say why
		skips := logs.FilterMessage("skipping project").All()
		require.Len(t, skips, 2)
		for _, entry := range skips {
			assert.Equal(t, "ignored in config", entry.ContextMap()["reason"])
		}
		assert.Equal(t, "https://gitlab.example.com/org/ignored.git", skips[1].ContextMap()["repo"])

		// every line came from the context logger, so it carries the source fields,
		// and none of them contain the token
		for _, entry := range logs.All() {
			fields := entry.ContextMap()
			assert.Contains(t, fields, "source_name", "line %q", entry.Message)
			assert.Contains(t, fields, "job_id", "line %q", entry.Message)
			assert.NotContains(t, entry.Message, testToken)
			assert.NotContains(t, fmt.Sprint(fields), testToken)
		}
	})

	t.Run("debug off", func(t *testing.T) {
		core, logs := observer.New(zapcore.InfoLevel)
		ctx := context.WithLogger(context.Background(), zapr.NewLogger(zap.New(core)))
		runSource(t, ctx)

		assert.Zero(t, logs.FilterMessage("skipping project").Len())
		assert.Zero(t, logs.FilterMessage("listed group projects").Len())
		assert.Zero(t, logs.FilterMessage("GitLab API request failed").Len())
		assert.Zero(t, logs.FilterMessage("Retrying GitLab API request").Len())
		assert.Zero(t, logs.FilterMessage("cache set: added project metadata in the cache").Len())
	})
}

func TestSource_EnumerateCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// the first request cancels the scan and hangs until the client gives up
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cancel()
		<-r.Context().Done()
	}))
	t.Cleanup(srv.Close)

	conn, err := anypb.New(&sourcespb.GitLab{
		Credential: &sourcespb.GitLab_Token{Token: "glpat-cancelledtestsecret"},
		Endpoint:   "https://gitlab.example.com",
		GroupIds:   []string{"1", "2", "3"},
	})
	require.NoError(t, err)

	s := Source{}
	require.NoError(t, s.Init(ctx, "test cancelled", 1, 1, false, conn, 1))
	s.url = srv.URL + "/"

	reporter := sourcestest.TestReporter{}
	err = s.Enumerate(ctx, &reporter)
	assert.ErrorIs(t, err, stdctx.Canceled)
	// the groups left are not reported as listing errors
	assert.Empty(t, reporter.UnitErrs)
}
