package github

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/google/go-github/v67/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

const (
	appDeniedMessage   = "Resource not accessible by integration"
	tokenDeniedMessage = "Resource not accessible by personal access token"
)

// forbidden builds the error go-github returns for a 403 to GET path, with the
// given message and acceptedPermissionsHeader value. An empty accepted omits
// the header.
func forbidden(path, message, accepted string) *github.ErrorResponse {
	header := http.Header{}
	if accepted != "" {
		header.Set(acceptedPermissionsHeader, accepted)
	}
	return &github.ErrorResponse{
		Response: &http.Response{
			StatusCode: http.StatusForbidden,
			Header:     header,
			Request:    &http.Request{Method: http.MethodGet, URL: &url.URL{Scheme: "https", Host: "api.github.com", Path: path, RawQuery: "per_page=100"}},
		},
		Message: message,
	}
}

func TestParseAcceptedPermissions(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   [][]permission
	}{
		{
			name:   "single permission",
			header: "issues=read",
			want:   [][]permission{{{name: "issues", access: "read"}}},
		},
		{
			name:   "several permissions all required",
			header: "pull_requests=write,contents=read",
			want:   [][]permission{{{name: "pull_requests", access: "write"}, {name: "contents", access: "read"}}},
		},
		{
			name:   "alternative sets",
			header: "pull_requests=read,contents=read; issues=read,contents=read",
			want: [][]permission{
				{{name: "pull_requests", access: "read"}, {name: "contents", access: "read"}},
				{{name: "issues", access: "read"}, {name: "contents", access: "read"}},
			},
		},
		{
			name:   "whitespace around entries",
			header: " issues = read ;pull_requests=read ",
			want:   [][]permission{{{name: "issues", access: "read"}}, {{name: "pull_requests", access: "read"}}},
		},
		{name: "empty", header: ""},
		{name: "blank", header: "   "},
		{name: "entry without access level", header: "issues"},
		{name: "empty entry", header: "issues=read,,contents=read"},
		{name: "empty alternative", header: "issues=read;"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, parseAcceptedPermissions(tt.header))
		})
	}
}

func TestPermissionErrorMessage(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantText string
	}{
		{
			name:     "GitHub App missing one permission",
			err:      forbidden("/repos/o/r/issues", appDeniedMessage, "issues=read"),
			wantText: "missing GitHub App permission: the request needs Issues (read); update the app's permissions and accept the change on the installation (GET /repos/o/r/issues returned 403 Resource not accessible by integration)",
		},
		{
			name:     "fine-grained token",
			err:      forbidden("/repos/o/r/pulls/comments", tokenDeniedMessage, "pull_requests=read"),
			wantText: "missing personal access token permission: the request needs Pull requests (read); update the token's permissions (GET /repos/o/r/pulls/comments returned 403 Resource not accessible by personal access token)",
		},
		{
			name:     "unrecognized credential gets a generic fix",
			err:      forbidden("/repos/o/r/issues", "Forbidden", "issues=read"),
			wantText: "missing GitHub permission: the request needs Issues (read); update the credential's permissions (GET /repos/o/r/issues returned 403 Forbidden)",
		},
		{
			name:     "single-permission alternatives",
			err:      forbidden("/repos/o/r/issues/comments", appDeniedMessage, "issues=read; pull_requests=read"),
			wantText: "the request needs Issues (read) or Pull requests (read);",
		},
		{
			name:     "several permissions required together",
			err:      forbidden("/repos/o/r/pulls", appDeniedMessage, "pull_requests=write,contents=read"),
			wantText: "the request needs Pull requests (write) and Contents (read);",
		},
		{
			name:     "alternatives needing several permissions each",
			err:      forbidden("/repos/o/r/issues/comments", appDeniedMessage, "pull_requests=read,contents=read; issues=read,contents=read"),
			wantText: "the request needs either Pull requests (read) and Contents (read), or Issues (read) and Contents (read);",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := asPermissionError(tt.err)
			var permErr *permissionError
			require.ErrorAs(t, got, &permErr)
			assert.Contains(t, got.Error(), tt.wantText)
			assert.ErrorIs(t, got, tt.err, "the original 403 stays reachable through Unwrap")
		})
	}
}

func TestPermissionErrorWithoutRequestStillReads(t *testing.T) {
	err := forbidden("/repos/o/r/issues", appDeniedMessage, "issues=read")
	err.Response.Request = nil

	got := asPermissionError(err)

	assert.Contains(t, got.Error(), "(request returned 403 Resource not accessible by integration)")
}

func TestAsPermissionErrorPassesOtherErrorsThrough(t *testing.T) {
	notFound := forbidden("/repos/o/r/issues", "Not Found", "issues=read")
	notFound.Response.StatusCode = http.StatusNotFound

	tests := []struct {
		name string
		err  error
	}{
		{name: "nil"},
		{name: "403 without the header", err: forbidden("/repos/o/r/issues", "Resource protected by organization SAML enforcement.", "")},
		{name: "403 with a header that doesn't parse", err: forbidden("/repos/o/r/issues", appDeniedMessage, "issues")},
		{name: "other status with the header", err: notFound},
		{name: "primary rate limit", err: &github.RateLimitError{Response: &http.Response{StatusCode: http.StatusForbidden}}},
		{name: "non-API error", err: errors.New("invalid pagination link")},
		{name: "403 without a response", err: &github.ErrorResponse{Message: appDeniedMessage}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := asPermissionError(tt.err)
			assert.Equal(t, tt.err, got)
			var permErr *permissionError
			assert.False(t, errors.As(got, &permErr))
		})
	}
}

func TestWalkPages_PermissionDeniedNamesMissingPermissionWithoutRetrying(t *testing.T) {
	listing := &fakeListing{
		records: sequentialRecords(7),
		fail: func(n int, w http.ResponseWriter, _ *http.Request) bool {
			if n != 2 {
				return false
			}
			w.Header().Set(acceptedPermissionsHeader, "issues=read")
			writeJSON(w, http.StatusForbidden, map[string]string{"message": appDeniedMessage})
			return true
		},
	}
	p := newTestPager(t, listing)
	waits := recordWaits(&p)

	var ids []int64
	outcome, err := walkPages(context.Background(), p, firstItems(p), collect(&ids))

	var permErr *permissionError
	require.ErrorAs(t, err, &permErr)
	assert.Equal(t, [][]permission{{{name: "issues", access: "read"}}}, permErr.accepted)
	assert.Equal(t, credentialApp, permErr.credential)
	assert.Contains(t, err.Error(), "GET /items returned 403 Resource not accessible by integration")
	assert.Empty(t, *waits, "a permission 403 is not retried")
	assert.Equal(t, 2, listing.requestCount())
	assert.Equal(t, 3, outcome.items)
	assert.Equal(t, idsUpTo(3), ids, "pages read before the 403 are kept")
}

func TestWalkUpdatedSince_PermissionErrorSurvivesWalkErrorWrapping(t *testing.T) {
	listing := &fakeListing{
		records: sequentialRecords(2),
		fail: func(_ int, w http.ResponseWriter, _ *http.Request) bool {
			w.Header().Set(acceptedPermissionsHeader, "pull_requests=read")
			writeJSON(w, http.StatusForbidden, map[string]string{"message": appDeniedMessage})
			return true
		},
	}
	p := newTestPager(t, listing)

	var ids []int64
	_, err := walkUpdatedSince(context.Background(), p, sinceItems(p, &ids))
	err = fmt.Errorf("pull request comments: %w", err)

	var permErr *permissionError
	require.ErrorAs(t, err, &permErr)
	assert.Contains(t, err.Error(), "pull request comments: walk incomplete after 0 items: missing GitHub App permission: the request needs Pull requests (read)")
}
