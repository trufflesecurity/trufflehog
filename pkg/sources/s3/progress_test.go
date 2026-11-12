package s3

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/feature"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sourcestest"
)

func TestUnitProgress_CountThenScan(t *testing.T) {
	var progress sources.Progress
	p := newUnitProgress("unit", &progress)

	p.setState(sources.UnitProgressCounting)
	p.counted(4, 4000, 1, 1000)

	got, ok := progress.GetUnitProgressFor("unit")
	require.True(t, ok)
	assert.Equal(t, sources.UnitProgress{
		State:        sources.UnitProgressCounting,
		ItemsDone:    1,
		ItemsTotal:   4,
		BytesDone:    1000,
		BytesTotal:   4000,
		ResumedBytes: 1000,
	}, got)
	assert.Zero(t, got.Percent(), "no percent while the total is still being counted")

	p.setState(sources.UnitProgressReady)
	p.objectDone(1000)

	got, _ = progress.GetUnitProgressFor("unit")
	assert.EqualValues(t, 2, got.ItemsDone)
	assert.EqualValues(t, 2000, got.BytesDone)
	assert.EqualValues(t, 50, got.Percent())
}

func TestUnitProgress_Finish(t *testing.T) {
	tests := []struct {
		name               string
		state              sources.UnitProgressState
		itemsTotal         uint64
		itemsDone          uint64
		scannedWholeBucket bool
		wantState          sources.UnitProgressState
		wantItemsTotal     uint64
	}{
		{
			name:  "counted, and objects added during the scan",
			state: sources.UnitProgressReady, itemsTotal: 4, itemsDone: 5, scannedWholeBucket: true,
			wantState: sources.UnitProgressReady, wantItemsTotal: 5,
		},
		{
			name:  "counted, and the scan listing broke off",
			state: sources.UnitProgressReady, itemsTotal: 4, itemsDone: 2,
			wantState: sources.UnitProgressReady, wantItemsTotal: 4,
		},
		{
			name:  "scan listed the whole bucket before the count finished",
			state: sources.UnitProgressCounting, itemsTotal: 1, itemsDone: 3, scannedWholeBucket: true,
			wantState: sources.UnitProgressReady, wantItemsTotal: 3,
		},
		{
			name:  "count failed but the scan listed the whole bucket",
			state: sources.UnitProgressUnavailable, itemsTotal: 1, itemsDone: 3, scannedWholeBucket: true,
			wantState: sources.UnitProgressReady, wantItemsTotal: 3,
		},
		{
			name:  "resumed scan finished before the count",
			state: sources.UnitProgressCounting, itemsTotal: 1, itemsDone: 3,
			wantState: sources.UnitProgressUnavailable, wantItemsTotal: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var progress sources.Progress
			p := newUnitProgress("unit", &progress)
			p.setState(tt.state)
			p.counted(tt.itemsTotal, tt.itemsTotal*100, 0, 0)
			for range tt.itemsDone {
				p.objectDone(100)
			}

			p.finish(tt.scannedWholeBucket)

			got, _ := progress.GetUnitProgressFor("unit")
			assert.Equal(t, tt.wantState, got.State)
			assert.Equal(t, tt.wantItemsTotal, got.ItemsTotal)
			assert.Equal(t, tt.wantItemsTotal*100, got.BytesTotal)
			assert.Equal(t, tt.itemsDone, got.ItemsDone)
		})
	}
}

func TestUnitProgress_IgnoresUpdatesAfterFinish(t *testing.T) {
	var progress sources.Progress
	p := newUnitProgress("unit", &progress)
	p.objectDone(100)
	p.finish(true)
	want, _ := progress.GetUnitProgressFor("unit")

	p.objectDone(100)
	p.counted(5, 500, 0, 0)
	p.setState(sources.UnitProgressUnavailable)

	got, _ := progress.GetUnitProgressFor("unit")
	assert.Equal(t, want, got)
}

func TestUnitProgress_NilIsANoOp(t *testing.T) {
	var p *unitProgress
	assert.NotPanics(t, func() { p.objectDone(100) })
}

// fakeBucket is a bucket served by fakeS3.
type fakeBucket struct {
	objects map[string]string
	// countDelay holds back listings that start from the beginning of the bucket, which only the count
	// makes when the scan is resumed, so a test can make the scan finish first.
	countDelay time.Duration
	// listPrefix denies listings outside it, as an IAM policy on s3:prefix does.
	listPrefix string
}

// fakeS3 serves the parts of the S3 API a unit scan uses, path style, two keys per page.
type fakeS3 struct {
	buckets   map[string]fakeBucket
	getDelay  time.Duration
	listCalls atomic.Int32
}

func (f *fakeS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	name, key, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
	bucket, ok := f.buckets[name]
	if !ok {
		http.Error(w, "no such bucket", http.StatusNotFound)
		return
	}

	if key == "" {
		f.list(w, r, name, bucket)
		return
	}

	if !sleep(r, f.getDelay) {
		return
	}
	body, ok := bucket.objects[key]
	if !ok {
		http.Error(w, "no such key", http.StatusNotFound)
		return
	}
	_, _ = w.Write([]byte(body))
}

func (f *fakeS3) list(w http.ResponseWriter, r *http.Request, name string, bucket fakeBucket) {
	f.listCalls.Add(1)
	const pageSize = 2

	query := r.URL.Query()
	prefix := query.Get("prefix")
	if !strings.HasPrefix(prefix, bucket.listPrefix) {
		http.Error(w, "access denied", http.StatusForbidden)
		return
	}

	after := query.Get("continuation-token")
	if after == "" {
		after = query.Get("start-after")
		if after == "" && !sleep(r, bucket.countDelay) {
			return
		}
	}

	keys := make([]string, 0, len(bucket.objects))
	for key := range bucket.objects {
		if strings.HasPrefix(key, prefix) && key > after {
			keys = append(keys, key)
		}
	}
	slices.Sort(keys)
	truncated := len(keys) > pageSize
	if truncated {
		keys = keys[:pageSize]
	}

	var b strings.Builder
	fmt.Fprintf(&b, `<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">`+
		`<Name>%s</Name><KeyCount>%d</KeyCount><MaxKeys>1000</MaxKeys><IsTruncated>%t</IsTruncated>`, name, len(keys), truncated)
	for _, key := range keys {
		fmt.Fprintf(&b, `<Contents><Key>%s</Key><LastModified>2024-01-01T00:00:00.000Z</LastModified><Size>%d</Size>`+
			`<StorageClass>STANDARD</StorageClass></Contents>`, key, len(bucket.objects[key]))
	}
	if truncated {
		fmt.Fprintf(&b, `<NextContinuationToken>%s</NextContinuationToken>`, keys[len(keys)-1])
	}
	b.WriteString(`</ListBucketResult>`)

	w.Header().Set("Content-Type", "application/xml")
	_, _ = w.Write([]byte(b.String()))
}

// sleep waits for d unless the request is cancelled first, and reports whether it waited the whole time.
func sleep(r *http.Request, d time.Duration) bool {
	if d == 0 {
		return true
	}
	select {
	case <-time.After(d):
		return true
	case <-r.Context().Done():
		return false
	}
}

// newFakeS3Source starts fake as an S3-compatible endpoint and returns a source initialized against it,
// after configure has adjusted the connection.
func newFakeS3Source(t *testing.T, fake *fakeS3, configure ...func(*sourcespb.S3)) *Source {
	t.Helper()
	server := httptest.NewServer(fake)
	t.Cleanup(server.Close)

	s3Conn := &sourcespb.S3{
		Credential: &sourcespb.S3_Unauthenticated{},
		Endpoint:   server.URL,
	}
	for _, f := range configure {
		f(s3Conn)
	}
	conn, err := anypb.New(s3Conn)
	require.NoError(t, err)

	s := &Source{}
	require.NoError(t, s.Init(context.Background(), "s3 test source", 0, 0, false, conn, 1))
	return s
}

func enableUnitProgress(t *testing.T) {
	t.Helper()
	feature.EnableS3UnitProgress.Store(true)
	t.Cleanup(func() { feature.EnableS3UnitProgress.Store(false) })
}

// testObjects are three objects of 10, 20 and 30 bytes, and one the scan skips as empty.
func testObjects() map[string]string {
	return map[string]string{
		"a.txt":     strings.Repeat("a", 10),
		"b.txt":     strings.Repeat("b", 20),
		"c.txt":     strings.Repeat("c", 30),
		"empty.txt": "",
	}
}

func TestSource_ChunkUnit_UnitProgress(t *testing.T) {
	enableUnitProgress(t)
	fake := &fakeS3{buckets: map[string]fakeBucket{"bucket": {objects: testObjects()}}}
	s := newFakeS3Source(t, fake)

	unit := S3SourceUnit{Bucket: "bucket"}
	reporter := sourcestest.TestReporter{}
	require.NoError(t, s.ChunkUnit(context.Background(), unit, &reporter))

	unitID, _ := unit.SourceUnitID()
	got, ok := s.GetUnitProgressFor(unitID)
	require.True(t, ok)
	assert.Equal(t, sources.UnitProgress{
		State:      sources.UnitProgressReady,
		ItemsDone:  3,
		ItemsTotal: 3,
		BytesDone:  60,
		BytesTotal: 60,
	}, got)
	assert.EqualValues(t, 99, got.Percent())
	assert.NotEmpty(t, reporter.Chunks)
}

func TestSource_ChunkUnit_ResumedUnitProgress(t *testing.T) {
	enableUnitProgress(t)
	// Slow downloads let the count finish first.
	fake := &fakeS3{buckets: map[string]fakeBucket{"bucket": {objects: testObjects()}}, getDelay: 200 * time.Millisecond}
	s := newFakeS3Source(t, fake)

	unit := S3SourceUnit{Bucket: "bucket"}
	unitID, _ := unit.SourceUnitID()
	s.SetEncodedResumeInfoFor(unitID, "a.txt")

	require.NoError(t, s.ChunkUnit(context.Background(), unit, &sourcestest.TestReporter{}))

	got, _ := s.GetUnitProgressFor(unitID)
	assert.Equal(t, sources.UnitProgress{
		State:        sources.UnitProgressReady,
		ItemsDone:    3,
		ItemsTotal:   3,
		BytesDone:    60,
		BytesTotal:   60,
		ResumedBytes: 10,
	}, got, "the object an earlier run finished counts as done")
}

// With one progress shared by every bucket, a count cut short in one bucket left the others at 0%.
// Each unit now has its own, so one bucket's count cannot affect another's.
func TestSource_ChunkUnit_UnitsDoNotShareProgress(t *testing.T) {
	enableUnitProgress(t)
	fake := &fakeS3{buckets: map[string]fakeBucket{
		"resumed": {objects: testObjects(), countDelay: 10 * time.Second},
		"fresh":   {objects: testObjects()},
	}}
	s := newFakeS3Source(t, fake)

	// The resumed scan finishes long before its count, which is cancelled.
	resumed := S3SourceUnit{Bucket: "resumed"}
	resumedID, _ := resumed.SourceUnitID()
	s.SetEncodedResumeInfoFor(resumedID, "a.txt")
	require.NoError(t, s.ChunkUnit(context.Background(), resumed, &sourcestest.TestReporter{}))

	fresh := S3SourceUnit{Bucket: "fresh"}
	require.NoError(t, s.ChunkUnit(context.Background(), fresh, &sourcestest.TestReporter{}))

	got, _ := s.GetUnitProgressFor(resumedID)
	assert.Equal(t, sources.UnitProgressUnavailable, got.State, "a resumed bucket with no count has no total")
	assert.EqualValues(t, 2, got.ItemsDone)
	assert.Zero(t, got.Percent())

	freshID, _ := fresh.SourceUnitID()
	got, _ = s.GetUnitProgressFor(freshID)
	assert.Equal(t, sources.UnitProgressReady, got.State)
	assert.EqualValues(t, 60, got.BytesTotal)
	assert.EqualValues(t, 99, got.Percent())
}

func TestSource_ChunkUnit_NoUnitProgressUnlessEnabled(t *testing.T) {
	fake := &fakeS3{buckets: map[string]fakeBucket{"bucket": {objects: testObjects()}}}
	s := newFakeS3Source(t, fake)

	unit := S3SourceUnit{Bucket: "bucket"}
	require.NoError(t, s.ChunkUnit(context.Background(), unit, &sourcestest.TestReporter{}))

	unitID, _ := unit.SourceUnitID()
	_, ok := s.GetUnitProgressFor(unitID)
	assert.False(t, ok)
	assert.EqualValues(t, 2, fake.listCalls.Load(), "only the scan lists the bucket")
}
