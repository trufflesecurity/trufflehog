package github

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/go-github/v67/github"
	"github.com/stretchr/testify/assert"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

func testClientForServer(t *testing.T, serverURL string) *github.Client {
	t.Helper()
	client := github.NewClient(nil)
	base, err := url.Parse(serverURL + "/")
	assert.NoError(t, err)
	client.BaseURL = base
	return client
}

// downloadByPathServer answers the exact-path contents lookup, the raw
// download it points at, and the repository lookup repoReachable makes.
func downloadByPathServer(t *testing.T, fileStatus, rawStatus, repoStatus int) *httptest.Server {
	t.Helper()
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/o/r/contents/dir/f.txt":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(fileStatus)
			if fileStatus == http.StatusOK {
				_, _ = fmt.Fprintf(w, `{"type":"file","name":"f.txt","path":"dir/f.txt","download_url":"%s/raw/dir/f.txt"}`, server.URL)
				return
			}
			_, _ = w.Write([]byte(`{"message":"Not Found"}`))
		case "/raw/dir/f.txt":
			w.WriteHeader(rawStatus)
			if rawStatus == http.StatusOK {
				_, _ = w.Write([]byte("file body"))
				return
			}
			_, _ = w.Write([]byte("raw host error page"))
		case "/repos/o/r":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(repoStatus)
			if repoStatus == http.StatusOK {
				_, _ = w.Write([]byte(`{"id":1,"name":"r","full_name":"o/r"}`))
				return
			}
			_, _ = w.Write([]byte(`{"message":"Not Found"}`))
		default:
			t.Errorf("unexpected request: %s", r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	return server
}

func TestDownloadContentsByPathFetchesFileBody(t *testing.T) {
	server := downloadByPathServer(t, http.StatusOK, http.StatusOK, http.StatusOK)
	defer server.Close()

	s := &Source{}
	client := testClientForServer(t, server.URL)
	rc, resp, err := s.downloadContentsByPath(context.Background(), client, "o", "r", "dir/f.txt", "abc123")
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(rc)
	assert.NoError(t, err)
	assert.NoError(t, rc.Close())
	assert.Equal(t, "file body", string(body))
}

func TestDownloadContentsByPathReturns404Response(t *testing.T) {
	server := downloadByPathServer(t, http.StatusNotFound, http.StatusOK, http.StatusOK)
	defer server.Close()

	s := &Source{}
	client := testClientForServer(t, server.URL)
	rc, resp, err := s.downloadContentsByPath(context.Background(), client, "o", "r", "dir/f.txt", "abc123")
	assert.Error(t, err)
	assert.Nil(t, rc)
	// The 404 is the exact-path lookup's, which the caller combines with
	// repoReachable to classify the target as gone.
	assert.NotNil(t, resp)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestDownloadContentsByPathNon404Failure(t *testing.T) {
	server := downloadByPathServer(t, http.StatusForbidden, http.StatusOK, http.StatusOK)
	defer server.Close()

	s := &Source{}
	client := testClientForServer(t, server.URL)
	_, resp, err := s.downloadContentsByPath(context.Background(), client, "o", "r", "dir/f.txt", "abc123")
	assert.Error(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestRepoReachable(t *testing.T) {
	server := downloadByPathServer(t, http.StatusNotFound, http.StatusOK, http.StatusOK)
	defer server.Close()

	s := &Source{}
	client := testClientForServer(t, server.URL)
	assert.True(t, s.repoReachable(context.Background(), client, "o", "r"))
}

func TestRepoNotReachable(t *testing.T) {
	server := downloadByPathServer(t, http.StatusNotFound, http.StatusOK, http.StatusNotFound)
	defer server.Close()

	s := &Source{}
	client := testClientForServer(t, server.URL)
	// The repo 404s too: could be lost access rather than deletion, so the
	// caller must not classify the target as gone.
	assert.False(t, s.repoReachable(context.Background(), client, "o", "r"))
}

func TestRepoReachableServerDown(t *testing.T) {
	server := downloadByPathServer(t, http.StatusNotFound, http.StatusOK, http.StatusOK)
	server.Close()

	s := &Source{}
	client := testClientForServer(t, server.URL)
	assert.False(t, s.repoReachable(context.Background(), client, "o", "r"))
}

func TestDownloadContentsByPathNon200Download(t *testing.T) {
	server := downloadByPathServer(t, http.StatusOK, http.StatusInternalServerError, http.StatusOK)
	defer server.Close()

	s := &Source{}
	client := testClientForServer(t, server.URL)
	rc, resp, err := s.downloadContentsByPath(context.Background(), client, "o", "r", "dir/f.txt", "abc123")
	assert.Error(t, err)
	assert.ErrorContains(t, err, "unexpected HTTP response status")
	assert.Nil(t, rc)
	// The returned response is the exact-path lookup's (200), not the failed
	// download's, so the caller cannot mistake a download failure for the
	// target being gone.
	assert.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}
