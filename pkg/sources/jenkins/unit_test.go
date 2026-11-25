package jenkins

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"slices"
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
	"github.com/trufflesecurity/trufflehog/v3/pkg/sourcestest"
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

// createMockJenkinsBuildsServer serves two jobs for the ChunkUnit tests:
//
//	/job/good       builds 1 and 2; build 2's log is forbidden when brokenLog is set
//	/job/no-builds  whose builds listing is forbidden
//
// Failures use 403 rather than 500 so the client's 5XX retry policy doesn't
// stall the tests.
func createMockJenkinsBuildsServer(brokenLog bool) *httptest.Server {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)

	mux.HandleFunc("/api/json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if !strings.Contains(r.URL.RawQuery, "tree=jobs") {
			_, _ = fmt.Fprint(w, `{"jobs":[]}`)
			return
		}
		_, _ = fmt.Fprintf(w, `{"jobs":[`+
			`{"_class":"org.jenkinsci.plugins.workflow.job.WorkflowJob","name":"good","url":"%[1]s/job/good/"},`+
			`{"_class":"hudson.model.FreeStyleProject","name":"no-builds","url":"%[1]s/job/no-builds/"}]}`, server.URL)
	})
	mux.HandleFunc("/job/good/api/json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"builds":[{"number":1,"url":"%[1]s/job/good/1/"},{"number":2,"url":"%[1]s/job/good/2/"}]}`, server.URL)
	})
	mux.HandleFunc("/job/good/1/consoleText", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "build one log")
	})
	mux.HandleFunc("/job/good/2/consoleText", func(w http.ResponseWriter, _ *http.Request) {
		if brokenLog {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_, _ = fmt.Fprint(w, "build two log")
	})
	mux.HandleFunc("/job/no-builds/api/json", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})

	return server
}

// buildNumbers returns the build number of every reported chunk, sorted.
func buildNumbers(t *testing.T, chunks []sources.Chunk) []int64 {
	t.Helper()
	numbers := make([]int64, 0, len(chunks))
	for _, chunk := range chunks {
		meta := chunk.SourceMetadata.GetJenkins()
		require.NotNil(t, meta)
		numbers = append(numbers, meta.BuildNumber)
	}
	slices.Sort(numbers)
	return numbers
}

func TestChunkUnit(t *testing.T) {
	server := createMockJenkinsBuildsServer(false)
	defer server.Close()

	ctx := context.Background()
	s := newTestSource(t, ctx, server.URL, "chunk-unit")

	reporter := &sourcestest.TestReporter{}
	require.NoError(t, s.ChunkUnit(ctx, JenkinsJob{Name: "good", Path: "/job/good"}, reporter))

	assert.Empty(t, reporter.ChunkErrs)
	assert.Equal(t, []int64{1, 2}, buildNumbers(t, reporter.Chunks))
	for _, chunk := range reporter.Chunks {
		meta := chunk.SourceMetadata.GetJenkins()
		assert.Equal(t, "good", meta.ProjectName)
		assert.Equal(t, fmt.Sprintf("%s/job/good/%d/consoleText", server.URL, meta.BuildNumber), meta.Link)
		assert.Equal(t, "chunk-unit", chunk.SourceName)
	}
}

func TestChunkUnitBuildListFails(t *testing.T) {
	server := createMockJenkinsBuildsServer(false)
	defer server.Close()

	ctx := context.Background()
	s := newTestSource(t, ctx, server.URL, "chunk-unit")

	reporter := &sourcestest.TestReporter{}
	require.NoError(t, s.ChunkUnit(ctx, JenkinsJob{Name: "no-builds", Path: "/job/no-builds"}, reporter),
		"a job-level failure is reported, not returned")

	assert.Empty(t, reporter.Chunks)
	require.Len(t, reporter.ChunkErrs, 1)
	assert.Contains(t, reporter.ChunkErrs[0].Error(), "/job/no-builds")
}

func TestChunkUnitOneBuildLogFails(t *testing.T) {
	server := createMockJenkinsBuildsServer(true)
	defer server.Close()

	ctx := context.Background()
	s := newTestSource(t, ctx, server.URL, "chunk-unit")

	reporter := &sourcestest.TestReporter{}
	require.NoError(t, s.ChunkUnit(ctx, JenkinsJob{Name: "good", Path: "/job/good"}, reporter))

	assert.Equal(t, []int64{1}, buildNumbers(t, reporter.Chunks), "the healthy build is still scanned")
	require.Len(t, reporter.ChunkErrs, 1)
	assert.Contains(t, reporter.ChunkErrs[0].Error(), "build 2")
}

func TestChunkUnitFromUnmarshalledUnit(t *testing.T) {
	server := createMockJenkinsBuildsServer(false)
	defer server.Close()

	ctx := context.Background()
	s := newTestSource(t, ctx, server.URL, "chunk-unit")

	full := JenkinsJob{
		Class: "org.jenkinsci.plugins.workflow.job.WorkflowJob",
		Name:  "good",
		Url:   server.URL + "/job/good/",
		Path:  "/job/good",
	}
	fullData, err := json.Marshal(full)
	require.NoError(t, err)

	tests := []struct {
		name     string
		envelope unitEnvelope
	}{
		{
			name:     "with unit_data",
			envelope: unitEnvelope{ID: "/job/good", Kind: "job", UnitData: base64.StdEncoding.EncodeToString(fullData)},
		},
		{
			// Rebuilt from the ID alone, so the project name comes from Display.
			name:     "id only",
			envelope: unitEnvelope{ID: "/job/good", Kind: "job"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.envelope)
			require.NoError(t, err)
			unit, err := s.UnmarshalSourceUnit(data)
			require.NoError(t, err)

			reporter := &sourcestest.TestReporter{}
			require.NoError(t, s.ChunkUnit(ctx, unit, reporter))

			assert.Empty(t, reporter.ChunkErrs)
			assert.Equal(t, []int64{1, 2}, buildNumbers(t, reporter.Chunks))
			for _, chunk := range reporter.Chunks {
				assert.Equal(t, "good", chunk.SourceMetadata.GetJenkins().ProjectName)
			}
		})
	}
}

// otherUnit is a SourceUnit that is not a JenkinsJob.
type otherUnit struct{}

func (otherUnit) SourceUnitID() (string, sources.SourceUnitKind) { return "other", "other" }
func (otherUnit) Display() string                                { return "other" }

func TestChunkUnitRejectsWrongUnitType(t *testing.T) {
	ctx := context.Background()
	s := newTestSource(t, ctx, "http://jenkins.invalid", "chunk-unit")

	reporter := &sourcestest.TestReporter{}
	assert.Error(t, s.ChunkUnit(ctx, otherUnit{}, reporter))
	assert.Empty(t, reporter.Chunks)
}

func TestChunkUnitCancelledContext(t *testing.T) {
	server := createMockJenkinsBuildsServer(false)
	defer server.Close()

	s := newTestSource(t, context.Background(), server.URL, "chunk-unit")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	reporter := &sourcestest.TestReporter{}
	err := s.ChunkUnit(ctx, JenkinsJob{Name: "good", Path: "/job/good"}, reporter)
	assert.ErrorIs(t, err, ctx.Err())
	assert.Empty(t, reporter.Chunks)
}

// TestChunkUnitCancelledDuringBuildLog cancels the scan while the last build's
// log is being fetched. The cancellation must be returned rather than reported
// as a fault of the job, as TestReporter, like the SourceManager's reporter,
// swallows reported errors.
func TestChunkUnitCancelledDuringBuildLog(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()

	mux.HandleFunc("/job/good/api/json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"builds":[{"number":1,"url":"%[1]s/job/good/1/"},{"number":2,"url":"%[1]s/job/good/2/"}]}`, server.URL)
	})
	mux.HandleFunc("/job/good/1/consoleText", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "build one log")
	})
	mux.HandleFunc("/job/good/2/consoleText", func(_ http.ResponseWriter, r *http.Request) {
		cancel()
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	})

	s := newTestSource(t, context.Background(), server.URL, "chunk-unit")

	reporter := &sourcestest.TestReporter{}
	err := s.ChunkUnit(ctx, JenkinsJob{Name: "good", Path: "/job/good"}, reporter)
	assert.ErrorIs(t, err, ctx.Err())
	assert.Empty(t, reporter.ChunkErrs, "a cancelled fetch is not a job error")
	assert.Equal(t, []int64{1}, buildNumbers(t, reporter.Chunks), "builds before the cancellation are still scanned")
}

// TestSourceManagerReportsErroredJobUnit runs the source through the
// SourceManager's unit path, checking that a job which fails is reported as an
// errored unit while the other job is still scanned.
func TestSourceManagerReportsErroredJobUnit(t *testing.T) {
	server := createMockJenkinsBuildsServer(false)
	defer server.Close()

	ctx := context.Background()
	s := newTestSource(t, ctx, server.URL, "chunk-unit")

	hook, metricsCh := sources.NewUnitHook(ctx)
	mgr := sources.NewManager(
		sources.WithBufferedOutput(8),
		sources.WithSourceUnits(),
		sources.WithConcurrentUnits(2),
		sources.WithReportHook(hook),
	)

	var chunks []*sources.Chunk
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		for chunk := range mgr.Chunks() {
			chunks = append(chunks, chunk)
		}
	}()

	ref, err := mgr.EnumerateAndScan(ctx, "jenkins", s)
	require.NoError(t, err)
	<-ref.Done()
	require.NoError(t, mgr.Wait(), "a failing job must not fail the scan")
	<-drained

	assert.Len(t, chunks, 2, "both builds of the healthy job are scanned")

	errorsByUnit := make(map[string]int)
	for metric := range metricsCh {
		id, _ := metric.Unit.SourceUnitID()
		errorsByUnit[id] = len(metric.Errors)
	}
	assert.Equal(t, map[string]int{"/job/good": 0, "/job/no-builds": 1}, errorsByUnit)
}
