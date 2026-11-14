package github_experimental

import (
	stdcontext "context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/go-github/v67/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest/observer"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/log/logtest"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
)

const testToken = "ghexperimentaldebuglogtesttoken"

// testClient returns a GitHub client that sends every request to server, with the
// test token as the bearer token, like the source's authenticated client.
func testClient(t *testing.T, server *httptest.Server) *github.Client {
	t.Helper()
	target, err := url.Parse(server.URL)
	require.NoError(t, err)
	return github.NewClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		req = req.Clone(req.Context())
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.Header.Set("Authorization", "Bearer "+testToken)
		return http.DefaultTransport.RoundTrip(req)
	})})
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestSource_DebugLogging(t *testing.T) {
	const hiddenOID = "abcd000000000000000000000000000000000000"

	conn, err := anypb.New(&sourcespb.GitHubExperimental{
		Repository:      "owner/repo",
		Credential:      &sourcespb.GitHubExperimental_Token{Token: testToken},
		ObjectDiscovery: true,
	})
	require.NoError(t, err)

	runSource := func(t *testing.T, debug bool) []observer.LoggedEntry {
		t.Helper()
		var requests atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			// The first request fails, so the retry line is logged.
			if requests.Add(1) == 1 {
				_, _ = fmt.Fprint(w, `{"errors":[{"message":"Something went wrong. Try again"}]}`)
				return
			}
			_, _ = fmt.Fprintf(w, `{"data":{"repository":{"commitabcd":{"oid":"%s"},"commitef01":null}}}`, hiddenOID)
		}))
		defer server.Close()

		ctx, logs := logtest.SourceContext(debug)
		s := new(Source)
		require.NoError(t, s.Init(ctx, "test source", 1, 1, false, conn, 1))
		if debug {
			logtest.CheckInitLine(t, logs.All())
		}

		dir := t.TempDir()
		require.NoError(t, processCommits(ctx, testClient(t, server), []string{"abcd", "ef01"}, "owner", "repo", dir))

		valid, err := readCommitsFromDisk(validHiddenCommit, dir)
		require.NoError(t, err)
		assert.Equal(t, []string{hiddenOID}, valid)
		invalid, err := readCommitsFromDisk(invalidCommit, dir)
		require.NoError(t, err)
		assert.Equal(t, []string{"ef01"}, invalid)
		return logs.All()
	}

	t.Run("debug on", func(t *testing.T) {
		logtest.CheckSourceLines(t, runSource(t, true), testToken)
	})

	t.Run("debug off", func(t *testing.T) {
		logtest.CheckNoDebugLines(t, runSource(t, false))
	})
}

func TestProcessCommits_StopsOnCancel(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("no request should be sent after cancel")
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := processCommits(ctx, testClient(t, server), []string{"abcd"}, "owner", "repo", t.TempDir())
	assert.ErrorIs(t, err, stdcontext.Canceled)
}

func TestProcessCommits_StopsAfterFailures(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = fmt.Fprint(w, `{"message":"Bad credentials"}`)
	}))
	defer server.Close()

	dir := t.TempDir()
	err := processCommits(context.Background(), testClient(t, server), []string{"abcd"}, "owner", "repo", dir)
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "Bad credentials"), err.Error())
	assert.Equal(t, int32(maxConsecutiveFailures), requests.Load())
	_, statErr := os.Stat(filepath.Join(dir, validHiddenCommit+".txt"))
	assert.True(t, os.IsNotExist(statErr))
}
