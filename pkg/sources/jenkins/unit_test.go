package jenkins

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/credentialspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

// testUnitReporter records everything Enumerate reports.
type testUnitReporter struct {
	mu    sync.Mutex
	units []sources.SourceUnit
	errs  []error
}

func (r *testUnitReporter) UnitOk(_ context.Context, unit sources.SourceUnit) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.units = append(r.units, unit)
	return nil
}

func (r *testUnitReporter) UnitErr(_ context.Context, err error) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.errs = append(r.errs, err)
	return nil
}

func (r *testUnitReporter) unitIDs(t *testing.T) []string {
	t.Helper()
	ids := make([]string, 0, len(r.units))
	for _, unit := range r.units {
		id, kind := unit.SourceUnitID()
		assert.Equal(t, SourceUnitKindJob, kind, "every Jenkins unit must use the job kind")
		ids = append(ids, id)
	}
	return ids
}

// createMockJenkinsTreeServer serves a nested job tree. The existing mock in
// jenkins_test.go has no folders, so folder recursion is only covered here.
//
//	/job/top-job                             WorkflowJob
//	/job/ignored-class                       MatrixProject, unsupported, dropped
//	/job/folder1/                            Folder
//	/job/folder1/job/nested-job              FreeStyleProject
//	/job/folder1/job/folder2/                Folder
//	/job/folder1/job/folder2/job/deep-job    WorkflowJob
//	/job/broken/                             Folder whose listing is forbidden
func createMockJenkinsTreeServer(withBrokenFolder bool) *httptest.Server {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)

	object := func(class, name, path string) string {
		return fmt.Sprintf(`{"_class":%q,"name":%q,"url":"%s%s"}`, class, name, server.URL, path)
	}
	jobsResponse := func(w http.ResponseWriter, r *http.Request, objects ...string) {
		w.Header().Set("Content-Type", "application/json")
		if !strings.Contains(r.URL.RawQuery, "tree=jobs") {
			_, _ = fmt.Fprint(w, `{"jobs":[]}`)
			return
		}
		_, _ = fmt.Fprintf(w, `{"jobs":[%s]}`, strings.Join(objects, ","))
	}

	root := []string{
		object("org.jenkinsci.plugins.workflow.job.WorkflowJob", "top-job", "/job/top-job/"),
		object("hudson.matrix.MatrixProject", "ignored-class", "/job/ignored-class/"),
		object("com.cloudbees.hudson.plugins.folder.Folder", "folder1", "/job/folder1/"),
	}
	if withBrokenFolder {
		root = append(root, object("com.cloudbees.hudson.plugins.folder.Folder", "broken", "/job/broken/"))
	}

	mux.HandleFunc("/api/json", func(w http.ResponseWriter, r *http.Request) {
		jobsResponse(w, r, root...)
	})
	mux.HandleFunc("/job/folder1/api/json", func(w http.ResponseWriter, r *http.Request) {
		jobsResponse(w, r,
			object("hudson.model.FreeStyleProject", "nested-job", "/job/folder1/job/nested-job/"),
			object("com.cloudbees.hudson.plugins.folder.Folder", "folder2", "/job/folder1/job/folder2/"))
	})
	mux.HandleFunc("/job/folder1/job/folder2/api/json", func(w http.ResponseWriter, r *http.Request) {
		jobsResponse(w, r,
			object("org.jenkinsci.plugins.workflow.job.WorkflowJob", "deep-job", "/job/folder1/job/folder2/job/deep-job/"))
	})
	// 403 rather than 500 so the client's 5XX retry policy doesn't stall the
	// test for the full 90s retry budget.
	mux.HandleFunc("/job/broken/api/json", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})

	return server
}

func newTestSource(t *testing.T, ctx context.Context, endpoint, name string) *Source {
	t.Helper()

	conn, err := anypb.New(&sourcespb.Jenkins{
		Endpoint: endpoint,
		Credential: &sourcespb.Jenkins_BasicAuth{
			BasicAuth: &credentialspb.BasicAuth{
				Username: "testuser",
				Password: "testpass",
			},
		},
	})
	require.NoError(t, err)

	s := new(Source)
	require.NoError(t, s.Init(ctx, name, 0, 1, false, conn, runtime.NumCPU()))
	return s
}

// wantedUnitIDs are the jobs the mock tree exposes, in the order the walk finds
// them. The unsupported MatrixProject and the folders themselves are excluded.
var wantedUnitIDs = []string{
	"/job/top-job",
	"/job/folder1/job/nested-job",
	"/job/folder1/job/folder2/job/deep-job",
}

func TestEnumerate(t *testing.T) {
	t.Parallel()

	server := createMockJenkinsTreeServer(false)
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	s := newTestSource(t, ctx, server.URL, "test-jenkins-enumerate")

	reporter := new(testUnitReporter)
	require.NoError(t, s.Enumerate(ctx, reporter))

	assert.Equal(t, wantedUnitIDs, reporter.unitIDs(t))
	assert.Empty(t, reporter.errs)
}

func TestEnumerateStableAcrossRuns(t *testing.T) {
	t.Parallel()

	server := createMockJenkinsTreeServer(false)
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	s := newTestSource(t, ctx, server.URL, "test-jenkins-stable")

	first := new(testUnitReporter)
	require.NoError(t, s.Enumerate(ctx, first))
	second := new(testUnitReporter)
	require.NoError(t, s.Enumerate(ctx, second))

	assert.Equal(t, first.unitIDs(t), second.unitIDs(t))
}

func TestEnumerateContinuesPastFolderError(t *testing.T) {
	t.Parallel()

	server := createMockJenkinsTreeServer(true)
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	s := newTestSource(t, ctx, server.URL, "test-jenkins-folder-error")

	reporter := new(testUnitReporter)
	require.NoError(t, s.Enumerate(ctx, reporter))

	// The unreadable folder is reported but does not stop the other jobs from
	// being enumerated.
	assert.Equal(t, wantedUnitIDs, reporter.unitIDs(t))
	require.Len(t, reporter.errs, 1)
	assert.Contains(t, reporter.errs[0].Error(), "/job/broken/")
}

// TestEnumerateMatchesChunkTraversal guards against Enumerate and the walk
// Chunks uses reporting different sets of jobs.
func TestEnumerateMatchesChunkTraversal(t *testing.T) {
	t.Parallel()

	server := createMockJenkinsTreeServer(false)
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	s := newTestSource(t, ctx, server.URL, "test-jenkins-parity")

	jobs, err := s.GetJenkinsJobs(ctx)
	require.NoError(t, err)

	reporter := new(testUnitReporter)
	require.NoError(t, s.Enumerate(ctx, reporter))

	require.Len(t, reporter.units, len(jobs.Jobs))
	for i, job := range jobs.Jobs {
		id, _ := reporter.units[i].SourceUnitID()
		assert.Equal(t, job.Path, id, "unit does not match the job Chunks would scan (%q)", job.Url)
		assert.True(t, strings.HasSuffix(job.Url, id+"/"),
			"job path %q was not derived from the job URL %q", job.Path, job.Url)
	}
}

// TestUnparseableJobURLSkippedByBothPaths pins that a job whose URL cannot be
// parsed drops out of enumeration and out of the walk Chunks uses, rather than
// failing either one.
func TestUnparseableJobURLSkippedByBothPaths(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()

	mux.HandleFunc("/api/json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if !strings.Contains(r.URL.RawQuery, "tree=jobs") {
			_, _ = fmt.Fprint(w, `{"jobs":[]}`)
			return
		}
		// The second URL has an invalid percent escape, which url.Parse rejects.
		_, _ = fmt.Fprintf(w, `{"jobs":[`+
			`{"_class":"hudson.model.FreeStyleProject","name":"good","url":"%s/job/good/"},`+
			`{"_class":"hudson.model.FreeStyleProject","name":"bad","url":"%s/job/%%zz/"}`+
			`]}`, server.URL, server.URL)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	s := newTestSource(t, ctx, server.URL, "test-jenkins-bad-job-url")

	reporter := new(testUnitReporter)
	require.NoError(t, s.Enumerate(ctx, reporter))
	assert.Equal(t, []string{"/job/good"}, reporter.unitIDs(t))
	assert.Empty(t, reporter.errs)

	jobs, err := s.GetJenkinsJobs(ctx)
	require.NoError(t, err)
	require.Len(t, jobs.Jobs, 1)
	assert.Equal(t, "/job/good", jobs.Jobs[0].Path)
}

// TestGetJenkinsJobsStillFailsFast pins the pre-existing behavior of the walk
// Chunks relies on: an unreadable folder aborts the traversal.
func TestGetJenkinsJobsStillFailsFast(t *testing.T) {
	t.Parallel()

	server := createMockJenkinsTreeServer(true)
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	s := newTestSource(t, ctx, server.URL, "test-jenkins-fail-fast")

	_, err := s.GetJenkinsJobs(ctx)
	require.Error(t, err)
}

func TestJenkinsJobDisplay(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		path string
		want string
	}{
		{name: "top level", path: "/job/build", want: "build"},
		{name: "nested", path: "/job/folder1/job/sub/job/build", want: "folder1/sub/build"},
		// A folder holding many jobs is the normal case, so the leaf name has
		// to survive into the display string or siblings would all render the
		// same. See TestJenkinsJobDisplaySiblingsDiffer.
		{name: "sibling in same folder", path: "/job/folder1/job/first", want: "folder1/first"},
		{name: "other sibling in same folder", path: "/job/folder1/job/second", want: "folder1/second"},
		{name: "instance base path", path: "/jenkins/job/folder1/job/build", want: "folder1/build"},
		{name: "job named job", path: "/job/job/job/build", want: "job/build"},
		{name: "trailing slash", path: "/job/build/", want: "build"},
		{name: "no job segment falls back", path: "/some/other/path", want: "/some/other/path"},
		{name: "empty falls back", path: "", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, JenkinsJob{Path: tt.path}.Display())
		})
	}
}

// TestJenkinsJobDisplaySiblingsDiffer pins the property that distinct jobs never
// collapse to the same display string, including jobs sharing a folder.
func TestJenkinsJobDisplaySiblingsDiffer(t *testing.T) {
	t.Parallel()

	paths := []string{
		"/job/folder1/job/a",
		"/job/folder1/job/b",
		"/job/folder1/job/sub/job/a",
		"/job/folder2/job/a",
		"/job/a",
	}

	seen := make(map[string]string, len(paths))
	for _, path := range paths {
		display := JenkinsJob{Path: path}.Display()
		if previous, ok := seen[display]; ok {
			t.Errorf("paths %q and %q both display as %q", previous, path, display)
		}
		seen[display] = path
	}
}

func TestJenkinsJobSourceUnitID(t *testing.T) {
	t.Parallel()

	id, kind := JenkinsJob{Path: "/job/folder1/job/build"}.SourceUnitID()
	assert.Equal(t, "/job/folder1/job/build", id)
	assert.Equal(t, SourceUnitKindJob, kind)
}

func TestUnmarshalSourceUnit(t *testing.T) {
	t.Parallel()

	const jobPath = "/job/folder1/job/build"

	unitData, err := json.Marshal(JenkinsJob{Path: jobPath})
	require.NoError(t, err)

	envelopeWithData, err := json.Marshal(unitEnvelope{
		ID:       jobPath,
		Kind:     string(SourceUnitKindJob),
		Display:  "folder1/build",
		UnitData: base64.StdEncoding.EncodeToString(unitData),
	})
	require.NoError(t, err)

	envelopeIDOnly, err := json.Marshal(unitEnvelope{
		ID:      jobPath,
		Kind:    string(SourceUnitKindJob),
		Display: "folder1/build",
	})
	require.NoError(t, err)

	tests := []struct {
		name    string
		data    []byte
		want    string
		wantErr bool
	}{
		{name: "envelope with unit data", data: envelopeWithData, want: jobPath},
		{name: "envelope without unit data", data: envelopeIDOnly, want: jobPath},
		{name: "bare unit", data: unitData, want: jobPath},
		{
			name:    "envelope with wrong kind",
			data:    fmt.Appendf(nil, `{"id":%q,"kind":"bucket"}`, jobPath),
			wantErr: true,
		},
		{name: "empty path", data: []byte(`{"path":""}`), wantErr: true},
		{name: "not json", data: []byte(`not json`), wantErr: true},
	}

	s := new(Source)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			unit, err := s.UnmarshalSourceUnit(tt.data)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)

			id, kind := unit.SourceUnitID()
			assert.Equal(t, tt.want, id)
			assert.Equal(t, SourceUnitKindJob, kind)
		})
	}
}
