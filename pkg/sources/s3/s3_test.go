package s3

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/kylelemons/godebug/pretty"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/credentialspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

func TestSource_Init_IncludeAndIgnoreBucketsError(t *testing.T) {
	conn, err := anypb.New(&sourcespb.S3{
		Credential: &sourcespb.S3_AccessKey{
			AccessKey: &credentialspb.KeySecret{
				Key:    "ignored for test",
				Secret: "ignore for test",
			},
		},
		Buckets:       []string{"a"},
		IgnoreBuckets: []string{"b"},
	})
	assert.NoError(t, err)

	s := Source{}
	err = s.Init(context.Background(), "s3 test source", 0, 0, false, conn, 1)

	assert.Error(t, err)
}

// TestSource_ListErrorsAreExpected pins down that the origin of the bucket list,
// not the presence of a role, decides whether a listing denial is fatal.
func TestSource_ListErrorsAreExpected(t *testing.T) {
	// Only the bucket list matters here. That an assumed role does not change the
	// answer is covered behaviorally by TestScanBucketSwallowsEnumerationDenials.
	tests := []struct {
		name    string
		buckets []string
		want    bool
	}{
		{
			name: "buckets discovered from credentials, denials are expected",
			want: true,
		},
		{
			name:    "explicit buckets, denials are errors",
			buckets: []string{"bucket-a"},
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn, err := anypb.New(&sourcespb.S3{
				Credential: &sourcespb.S3_AccessKey{
					AccessKey: &credentialspb.KeySecret{
						Key:    "ignored for test",
						Secret: "ignored for test",
					},
				},
				Buckets: tt.buckets,
			})
			require.NoError(t, err)

			s := Source{}
			require.NoError(t, s.Init(context.Background(), "s3 test source", 0, 0, false, conn, 1))

			assert.Equal(t, tt.want, s.listErrorsAreExpected())
		})
	}
}

func TestSource_ScanBucketsReportsCumulativeObjectCount(t *testing.T) {
	conn, err := anypb.New(&sourcespb.S3{
		Credential: &sourcespb.S3_Unauthenticated{},
	})
	require.NoError(t, err)

	s := Source{}
	require.NoError(t, s.Init(context.Background(), "s3 test source", 0, 0, false, conn, 1))

	// Simulate a later role pass after an earlier pass already scanned three
	// objects. The pass below scans no buckets, so the completion message must
	// still report the cumulative total rather than resetting to zero.
	totalObjectCount := uint64(3)
	require.NoError(t, s.scanBuckets(context.Background(), nil, "", nil, make(chan *sources.Chunk, 1), &totalObjectCount))

	assert.Equal(t, uint64(3), totalObjectCount)
	assert.Contains(t, s.Message, "3 objects scanned")
}

// listObjectsServer stands in for S3 without needing AWS. It denies the named
// buckets and records which were asked for, so tests can prove a scan kept going
// after a failure. Custom endpoints use path-style addressing, so the bucket
// arrives as the first URL path segment.
type listObjectsServer struct {
	*httptest.Server

	// inventory is returned by ListBuckets, driving the discovery path. Set it
	// before issuing requests; the handler reads it unlocked.
	inventory []string

	// onRequest runs while a listing request is in flight, letting a test cancel
	// the scan mid-call rather than before it starts. Set it before issuing
	// requests; the handler reads it unlocked.
	onRequest func(bucket string)

	mu        sync.Mutex
	requested []string
}

func newListObjectsServer(t *testing.T, deniedBuckets ...string) *listObjectsServer {
	t.Helper()

	denied := make(map[string]struct{}, len(deniedBuckets))
	for _, bucket := range deniedBuckets {
		denied[bucket] = struct{}{}
	}

	srv := &listObjectsServer{}
	srv.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bucket := strings.Trim(r.URL.Path, "/")
		w.Header().Set("Content-Type", "application/xml")

		// A request to the service root is ListBuckets: the discovery call the
		// scanner makes when no buckets are configured.
		if bucket == "" {
			var entries strings.Builder
			for _, name := range srv.inventory {
				fmt.Fprintf(&entries, `<Bucket><Name>%s</Name><CreationDate>2026-01-01T00:00:00.000Z</CreationDate></Bucket>`, name)
			}
			_, _ = fmt.Fprintf(
				w,
				`<?xml version="1.0" encoding="UTF-8"?><ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">`+
					`<Owner><ID>fake</ID><DisplayName>fake</DisplayName></Owner><Buckets>%s</Buckets></ListAllMyBucketsResult>`,
				entries.String(),
			)
			return
		}

		srv.mu.Lock()
		srv.requested = append(srv.requested, bucket)
		srv.mu.Unlock()

		if srv.onRequest != nil {
			srv.onRequest(bucket)
		}

		if _, isDenied := denied[bucket]; isDenied {
			w.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprint(w, `<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>`)
			return
		}
		_, _ = fmt.Fprintf(
			w,
			`<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">`+
				`<Name>%s</Name><KeyCount>0</KeyCount><IsTruncated>false</IsTruncated></ListBucketResult>`,
			bucket,
		)
	}))
	t.Cleanup(srv.Close)

	return srv
}

// requestedBuckets returns the buckets the scanner tried to list, in order.
func (l *listObjectsServer) requestedBuckets() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.requested)
}

// newTestSource builds an initialized Source pointed at srv. An empty buckets
// list means the source discovers buckets from credentials, which is what makes
// listing denials expected rather than fatal.
func newTestSource(t *testing.T, srv *listObjectsServer, buckets ...string) *Source {
	t.Helper()

	conn, err := anypb.New(&sourcespb.S3{
		Credential: &sourcespb.S3_Unauthenticated{},
		Endpoint:   srv.URL,
		Buckets:    buckets,
	})
	require.NoError(t, err)

	s := &Source{}
	require.NoError(t, s.Init(context.Background(), "s3 test source", 0, 0, false, conn, 1))

	return s
}

func TestChunkUnitReturnsErrorWhenConfiguredBucketListIsDenied(t *testing.T) {
	srv := newListObjectsServer(t, "private-bucket")
	s := newTestSource(t, srv, "private-bucket")

	err := s.ChunkUnit(context.Background(), S3SourceUnit{Bucket: "private-bucket"}, sources.ChanReporter{Ch: make(chan *sources.Chunk, 1)})
	require.Error(t, err)
	assert.ErrorContains(t, err, `could not list objects in configured bucket "private-bucket"`)
}

// TestScanBucketSwallowsEnumerationDenials covers buckets that came from
// enumeration: denials are expected there, with or without a role in play.
func TestScanBucketSwallowsEnumerationDenials(t *testing.T) {
	for _, role := range []string{"", "arn:aws:iam::123456789012:role/some-role"} {
		name := "no role"
		if role != "" {
			name = "assumed role"
		}

		t.Run(name, func(t *testing.T) {
			srv := newListObjectsServer(t, "denied-bucket")
			s := newTestSource(t, srv)

			client, err := s.newClient(context.Background(), s.defaultRegion(), "")
			require.NoError(t, err)

			_, err = s.scanBucket(
				context.Background(),
				client,
				role,
				"denied-bucket",
				sources.ChanReporter{Ch: make(chan *sources.Chunk, 1)},
				nil,
				NewCheckpointer(context.Background(), &s.Progress, false),
			)
			require.NoError(t, err)
		})
	}
}

// TestScanBucketsAttemptsEveryBucketAndConsolidatesErrors is the regression test
// for stopping the whole pass on the first bad bucket: the buckets after a failure
// must still be scanned, and every failure must appear in the returned error.
func TestScanBucketsAttemptsEveryBucketAndConsolidatesErrors(t *testing.T) {
	buckets := []string{"denied-one", "allowed", "denied-two"}

	srv := newListObjectsServer(t, "denied-one", "denied-two")
	s := newTestSource(t, srv, buckets...)

	client, err := s.newClient(context.Background(), s.defaultRegion(), "")
	require.NoError(t, err)

	var totalObjectCount uint64
	err = s.scanBuckets(
		context.Background(),
		client,
		"",
		buckets,
		make(chan *sources.Chunk, 1),
		&totalObjectCount,
	)

	require.Error(t, err)
	assert.ErrorContains(t, err, `could not list objects in configured bucket "denied-one"`)
	assert.ErrorContains(t, err, `could not list objects in configured bucket "denied-two"`)
	assert.Equal(t, buckets, srv.requestedBuckets(), "every configured bucket should be attempted")

	// The pass reached the end of the list, so resume info is cleared on purpose:
	// the checkpointer has moved past the failed buckets, and keeping it would make
	// the retry skip them.
	assert.Empty(t, s.EncodedResumeInfo)
	assert.Contains(t, s.Message, "Completed scanning source")
}

// TestChunksReportsConfiguredBucketFailures checks that collecting failures inside
// the visitor still surfaces them from Chunks, and that the buckets after a failure
// are scanned rather than skipped.
func TestChunksReportsConfiguredBucketFailures(t *testing.T) {
	srv := newListObjectsServer(t, "denied-one")
	s := newTestSource(t, srv, "denied-one", "allowed")

	err := s.Chunks(context.Background(), make(chan *sources.Chunk, 4))
	require.Error(t, err)
	assert.ErrorContains(t, err, `could not list objects in configured bucket "denied-one"`)
	// getBucketsToScan sorts the configured list so an interrupted scan resumes in a
	// stable order, which puts "allowed" first regardless of how it was configured.
	assert.Equal(t, []string{"allowed", "denied-one"}, srv.requestedBuckets())
}

// TestVisitRolesStopsAtFirstError documents the constraint that makes Chunks
// collect its per-role failures instead of returning them: one visitor error
// abandons every remaining role.
func TestVisitRolesStopsAtFirstError(t *testing.T) {
	roles := []string{
		"arn:aws:iam::123456789012:role/role-a",
		"arn:aws:iam::123456789012:role/role-b",
	}

	srv := newListObjectsServer(t)
	conn, err := anypb.New(&sourcespb.S3{
		Credential: &sourcespb.S3_Unauthenticated{},
		Endpoint:   srv.URL,
		Buckets:    []string{"bucket-a"},
		Roles:      roles,
	})
	require.NoError(t, err)

	s := Source{}
	require.NoError(t, s.Init(context.Background(), "s3 test source", 0, 0, false, conn, 1))

	var visited []string
	recordVisit := func(roleArn string) { visited = append(visited, roleArn) }

	err = s.visitRoles(context.Background(), func(_ context.Context, _ *awss3.Client, roleArn string, _ []string) error {
		recordVisit(roleArn)
		return fmt.Errorf("bucket unreachable under %s", roleArn)
	})
	require.Error(t, err)
	assert.Equal(t, roles[:1], visited, "an error from the visitor skips the remaining roles")

	// The visitor Chunks installs swallows bucket failures for exactly this reason.
	visited = nil
	require.NoError(t, s.visitRoles(context.Background(), func(_ context.Context, _ *awss3.Client, roleArn string, _ []string) error {
		recordVisit(roleArn)
		return nil
	}))
	assert.Equal(t, roles, visited)
}

// TestChunksTreatsCancellationAsCleanStop guards the reviewer's rule that a
// context error must not make the scan unhealthy.
func TestChunksTreatsCancellationAsCleanStop(t *testing.T) {
	srv := newListObjectsServer(t)
	s := newTestSource(t, srv, "bucket-a")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	assert.NoError(t, s.Chunks(ctx, make(chan *sources.Chunk, 1)))
}

// TestChunkUnitResumeInfoLifecycle pins the rule that only a completed unit scan
// clears its resume info; a failed or interrupted one must be able to pick up
// where it stopped instead of starting the bucket over.
func TestChunkUnitResumeInfoLifecycle(t *testing.T) {
	const resumeKey = "objects/last-scanned-key"

	t.Run("failure keeps resume info", func(t *testing.T) {
		srv := newListObjectsServer(t, "private-bucket")
		s := newTestSource(t, srv, "private-bucket")

		unit := S3SourceUnit{Bucket: "private-bucket"}
		unitID, _ := unit.SourceUnitID()
		s.SetEncodedResumeInfoFor(unitID, resumeKey)

		err := s.ChunkUnit(context.Background(), unit, sources.ChanReporter{Ch: make(chan *sources.Chunk, 1)})
		require.Error(t, err)
		assert.Equal(t, resumeKey, s.GetEncodedResumeInfoFor(unitID))
	})

	t.Run("cancellation keeps resume info and is not an error", func(t *testing.T) {
		srv := newListObjectsServer(t)
		s := newTestSource(t, srv, "bucket-a")

		unit := S3SourceUnit{Bucket: "bucket-a"}
		unitID, _ := unit.SourceUnitID()
		s.SetEncodedResumeInfoFor(unitID, resumeKey)

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		require.NoError(t, s.ChunkUnit(ctx, unit, sources.ChanReporter{Ch: make(chan *sources.Chunk, 1)}))
		assert.Equal(t, resumeKey, s.GetEncodedResumeInfoFor(unitID))
	})

	t.Run("completion clears resume info", func(t *testing.T) {
		srv := newListObjectsServer(t)
		s := newTestSource(t, srv, "bucket-a")

		unit := S3SourceUnit{Bucket: "bucket-a"}
		unitID, _ := unit.SourceUnitID()
		s.SetEncodedResumeInfoFor(unitID, resumeKey)

		require.NoError(t, s.ChunkUnit(context.Background(), unit, sources.ChanReporter{Ch: make(chan *sources.Chunk, 1)}))
		assert.Empty(t, s.GetEncodedResumeInfoFor(unitID))
	})
}

// TestChunksDiscoveredBucketDenialsAreHealthy drives discovery end to end: with
// no buckets named, a denial on one the scanner found itself must be skipped
// rather than failing the scan.
func TestChunksDiscoveredBucketDenialsAreHealthy(t *testing.T) {
	srv := newListObjectsServer(t, "denied-bucket")
	srv.inventory = []string{"denied-bucket", "ok-bucket"}
	s := newTestSource(t, srv) // no configured buckets: discovery mode

	require.NoError(t, s.Chunks(context.Background(), make(chan *sources.Chunk, 4)))
	assert.Equal(t, []string{"denied-bucket", "ok-bucket"}, srv.requestedBuckets(),
		"the denied bucket must be skipped, not abort discovery scanning")
}

// cancelWhileListing makes the server cancel the scan as a listing request
// arrives, so the error surfaces from inside the AWS SDK instead of from the
// check at the top of scanBucket. The pause gives the client time to notice the
// cancellation rather than reading a complete response first.
func cancelWhileListing(srv *listObjectsServer, target string, cancel context.CancelFunc) {
	srv.onRequest = func(bucket string) {
		if target != "" && bucket != target {
			return
		}
		cancel()
		time.Sleep(50 * time.Millisecond)
	}
}

// TestChunkUnitDiscoveryCancellationKeepsResumeInfo covers cancellation arriving
// while a discovered bucket is being listed. Denials are expected on that path,
// so without a cancellation check first the interrupted bucket looks like a
// completed one and loses the checkpoint it had already written.
func TestChunkUnitDiscoveryCancellationKeepsResumeInfo(t *testing.T) {
	const resumeKey = "objects/last-scanned-key"

	srv := newListObjectsServer(t)
	s := newTestSource(t, srv) // no configured buckets: discovery mode

	unit := S3SourceUnit{Bucket: "bucket-a"}
	unitID, _ := unit.SourceUnitID()
	s.SetEncodedResumeInfoFor(unitID, resumeKey)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cancelWhileListing(srv, "", cancel)

	// Cancellation is still a clean stop, but the unit did not finish, so its
	// resume point has to survive.
	require.NoError(t, s.ChunkUnit(ctx, unit, sources.ChanReporter{Ch: make(chan *sources.Chunk, 1)}))
	assert.Equal(t, resumeKey, s.GetEncodedResumeInfoFor(unitID))
}

// TestScanBucketsInterruptRewindsResumeToFirstFailure guards the seam between
// collecting bucket failures and stopping early. The first bucket is denied, the
// second checkpoints an object and is then interrupted; without a rewind the
// checkpoint points at the second bucket, so the retry starts past the denied one
// and it silently drops out of the scan.
func TestScanBucketsInterruptRewindsResumeToFirstFailure(t *testing.T) {
	const (
		deniedBucket      = "a-denied"
		interruptedBucket = "b-interrupted"
	)
	buckets := []string{deniedBucket, interruptedBucket, "c-unreached"}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	page1 := `<?xml version="1.0" encoding="UTF-8"?>` +
		`<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">` +
		`<Name>` + interruptedBucket + `</Name><KeyCount>1</KeyCount><IsTruncated>true</IsTruncated>` +
		`<NextContinuationToken>page-2-token</NextContinuationToken>` +
		`<Contents><Key>obj-b.txt</Key><Size>12</Size>` +
		`<LastModified>2026-01-01T00:00:00.000Z</LastModified></Contents></ListBucketResult>`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.Trim(r.URL.Path, "/")

		if path == interruptedBucket+"/obj-b.txt" {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = fmt.Fprint(w, "hello secret")
			return
		}

		w.Header().Set("Content-Type", "application/xml")
		if path == deniedBucket {
			w.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprint(w, `<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>`)
			return
		}

		// Page one checkpoints obj-b.txt; the follow-up page is where the scan is
		// interrupted, so the checkpoint is already sitting on the second bucket.
		if r.URL.Query().Get("continuation-token") == "page-2-token" {
			cancel()
			time.Sleep(50 * time.Millisecond)
			return
		}
		if path == interruptedBucket {
			_, _ = fmt.Fprint(w, page1)
			return
		}
		_, _ = fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?>`+
			`<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">`+
			`<Name>%s</Name><KeyCount>0</KeyCount><IsTruncated>false</IsTruncated></ListBucketResult>`, path)
	}))
	t.Cleanup(srv.Close)

	conn, err := anypb.New(&sourcespb.S3{
		Credential: &sourcespb.S3_Unauthenticated{},
		Endpoint:   srv.URL,
		Buckets:    buckets,
	})
	require.NoError(t, err)

	s := &Source{}
	require.NoError(t, s.Init(context.Background(), "s3 test source", 0, 0, false, conn, 1))

	client, err := s.newClient(context.Background(), s.defaultRegion(), "")
	require.NoError(t, err)

	var totalObjectCount uint64
	err = s.scanBuckets(ctx, client, "", buckets, make(chan *sources.Chunk, 8), &totalObjectCount)

	require.Error(t, err)
	assert.ErrorContains(t, err, `could not list objects in configured bucket "a-denied"`)
	assert.Contains(t, s.EncodedResumeInfo, deniedBucket,
		"resume must rewind to the failed bucket so the retry attempts it again")
	assert.NotContains(t, s.EncodedResumeInfo, interruptedBucket,
		"resume must not start past a bucket that still needs another attempt")
}

// TestChunkUnitMidBucketFailureKeepsCheckpointedResume exercises the real
// checkpointer rather than a pre-seeded resume value: page one is scanned, page
// two is denied, and the checkpoint must survive so a retry does not start over.
func TestChunkUnitMidBucketFailureKeepsCheckpointedResume(t *testing.T) {
	const bucket = "resume-bucket"

	page1 := `<?xml version="1.0" encoding="UTF-8"?>` +
		`<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">` +
		`<Name>` + bucket + `</Name><KeyCount>2</KeyCount><IsTruncated>true</IsTruncated>` +
		`<NextContinuationToken>page-2-token</NextContinuationToken>` +
		`<Contents><Key>obj-a.txt</Key><Size>12</Size><LastModified>2026-01-01T00:00:00.000Z</LastModified></Contents>` +
		`<Contents><Key>obj-b.txt</Key><Size>12</Size><LastModified>2026-01-01T00:00:00.000Z</LastModified></Contents>` +
		`</ListBucketResult>`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.Trim(r.URL.Path, "/")

		// GetObject: path-style requests for object bodies scanned from page one.
		if strings.HasPrefix(path, bucket+"/") {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = fmt.Fprint(w, "hello secret")
			return
		}

		w.Header().Set("Content-Type", "application/xml")
		if r.URL.Query().Get("continuation-token") == "page-2-token" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprint(w, `<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>`)
			return
		}
		_, _ = fmt.Fprint(w, page1)
	}))
	t.Cleanup(srv.Close)

	conn, err := anypb.New(&sourcespb.S3{
		Credential: &sourcespb.S3_Unauthenticated{},
		Endpoint:   srv.URL,
		Buckets:    []string{bucket},
	})
	require.NoError(t, err)

	s := &Source{}
	require.NoError(t, s.Init(context.Background(), "s3 test source", 0, 0, false, conn, 1))

	unit := S3SourceUnit{Bucket: bucket}
	unitID, _ := unit.SourceUnitID()

	// The chunk channel must hold everything page one produces, since nothing
	// drains it while ChunkUnit runs.
	err = s.ChunkUnit(context.Background(), unit, sources.ChanReporter{Ch: make(chan *sources.Chunk, 16)})
	require.Error(t, err)
	assert.ErrorContains(t, err, `could not list objects in configured bucket "resume-bucket"`)

	// pageChunker waits for page one's objects before page two is requested, so
	// the checkpoint deterministically points at the last page-one key.
	assert.Equal(t, "obj-b.txt", s.GetEncodedResumeInfoFor(unitID),
		"checkpoint written during page one must survive the page-two failure")
}

func TestSource_Chunks(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()

	secret, err := common.GetTestSecret(ctx)
	if err != nil {
		t.Fatal(fmt.Errorf("failed to access secret: %v", err))
	}

	s3key := secret.MustGetField("AWS_S3_KEY")
	s3secret := secret.MustGetField("AWS_S3_SECRET")

	type init struct {
		name       string
		verify     bool
		connection *sourcespb.S3
		setEnv     map[string]string
	}
	tests := []struct {
		name          string
		init          init
		wantErr       bool
		wantChunkData string
	}{
		{
			name: "gets chunks",
			init: init{
				connection: &sourcespb.S3{
					Credential: &sourcespb.S3_AccessKey{
						AccessKey: &credentialspb.KeySecret{
							Key:    s3key,
							Secret: s3secret,
						},
					},
					Buckets: []string{"truffletestbucket-s3-tests"},
				},
			},
			wantErr:       false,
			wantChunkData: `W2RlZmF1bHRdCmF3c19hY2Nlc3Nfa2V5X2lkID0gQUtJQTM1T0hYMkRTT1pHNjQ3TkgKYXdzX3NlY3JldF9hY2Nlc3Nfa2V5ID0gUXk5OVMrWkIvQ1dsRk50eFBBaWQ3Z0d6dnNyWGhCQjd1ckFDQUxwWgpvdXRwdXQgPSBqc29uCnJlZ2lvbiA9IHVzLWVhc3QtMg==`,
		},
		{
			name: "gets chunks after assuming role",
			// This test will attempt to scan every bucket in the account, but the role policy blocks access to every
			// bucket except the one we want. This (expected behavior) causes errors in the test log output, but these
			// errors shouldn't actually cause test failures.
			init: init{
				connection: &sourcespb.S3{
					Roles: []string{"arn:aws:iam::619888638459:role/s3-test-assume-role"},
				},
				setEnv: map[string]string{
					"AWS_ACCESS_KEY_ID":     s3key,
					"AWS_SECRET_ACCESS_KEY": s3secret,
				},
			},
			wantErr:       false,
			wantChunkData: `W2RlZmF1bHRdCmF3c19zZWNyZXRfYWNjZXNzX2tleSA9IFF5OTlTK1pCL0NXbEZOdHhQQWlkN2dHenZzclhoQkI3dXJBQ0FMcFoKYXdzX2FjY2Vzc19rZXlfaWQgPSBBS0lBMzVPSFgyRFNPWkc2NDdOSApvdXRwdXQgPSBqc29uCnJlZ2lvbiA9IHVzLWVhc3QtMg==`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "gets chunks after assuming role" {
				t.Skip("skipping until our test environment stabilizes enough that we know how we're going to handle this")
			}

			ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
			defer cancel()

			for k, v := range tt.init.setEnv {
				t.Setenv(k, v)
			}

			s := Source{}
			conn, err := anypb.New(tt.init.connection)
			if err != nil {
				t.Fatal(err)
			}

			err = s.Init(ctx, tt.init.name, 0, 0, tt.init.verify, conn, 8)
			if (err != nil) != tt.wantErr {
				t.Errorf("Source.Init() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			chunksCh := make(chan *sources.Chunk, 1)
			go func() {
				defer close(chunksCh)
				err = s.Chunks(ctx, chunksCh)
				if (err != nil) != tt.wantErr {
					t.Errorf("Source.Chunks() error = %v, wantErr %v", err, tt.wantErr)
					os.Exit(1)
				}
			}()

			waitFn := func() {
				receivedFirstChunk := false
				for {
					select {
					case <-ctx.Done():
						t.Errorf("TestSource_Chunks timed out: %v", ctx.Err())
						return
					case gotChunk, ok := <-chunksCh:
						if !ok {
							t.Logf("Source.Chunks() finished, channel closed")
							assert.Equal(t, "", s.GetProgress().EncodedResumeInfo)
							assert.Equal(t, int64(100), s.GetProgress().PercentComplete)
							return
						}
						if receivedFirstChunk {
							// wantChunkData is the first chunk data. After the first chunk has
							// been received and matched below, we want to drain chunksCh
							// so Source.Chunks() can finish completely.
							continue
						}

						receivedFirstChunk = true
						wantData, _ := base64.StdEncoding.DecodeString(tt.wantChunkData)

						if diff := pretty.Compare(gotChunk.Data, wantData); diff != "" {
							t.Logf("%s: Source.Chunks() diff: (-got +want)\n%s", tt.name, diff)
						}
					}
				}
			}
			waitFn()
		})
	}
}

func TestSource_UnmarshalSourceUnit(t *testing.T) {
	roleARN := "arn:aws:iam::123456789012:role/my-role"

	// envelope mirrors the JSON shape thog persists between the enumerate and
	// scan passes: the SourceUnit proto marshalled with encoding/json, where
	// unit_data (if present) is the original unit as base64-encoded bytes.
	type envelope struct {
		ID       string `json:"id"`
		Kind     string `json:"kind,omitempty"`
		Display  string `json:"display,omitempty"`
		UnitData string `json:"unit_data,omitempty"`
	}

	marshalEnvelope := func(t *testing.T, id string, kind string, unit *S3SourceUnit) []byte {
		t.Helper()
		env := envelope{ID: id, Kind: kind, Display: id}
		if unit != nil {
			raw, err := json.Marshal(unit)
			require.NoError(t, err)
			env.UnitData = base64.StdEncoding.EncodeToString(raw)
		}
		data, err := json.Marshal(env)
		require.NoError(t, err)
		return data
	}

	tests := []struct {
		name     string
		data     []byte
		wantUnit S3SourceUnit
		wantErr  bool
	}{
		{
			name:     "bare unit, role-bearing ARN",
			data:     []byte(`{"Bucket":"my-test-bucket","Role":"` + roleARN + `"}`),
			wantUnit: S3SourceUnit{Bucket: "my-test-bucket", Role: roleARN},
		},
		{
			name:     "bare unit, role-less",
			data:     []byte(`{"Bucket":"my-test-bucket"}`),
			wantUnit: S3SourceUnit{Bucket: "my-test-bucket"},
		},
		{
			name: "envelope with unit_data, role-bearing",
			data: marshalEnvelope(t, constructS3SourceUnitID("my-test-bucket", roleARN), "bucket",
				&S3SourceUnit{Bucket: "my-test-bucket", Role: roleARN}),
			wantUnit: S3SourceUnit{Bucket: "my-test-bucket", Role: roleARN},
		},
		{
			name: "envelope with unit_data, role-less",
			data: marshalEnvelope(t, constructS3SourceUnitID("my-test-bucket", ""), "bucket",
				&S3SourceUnit{Bucket: "my-test-bucket"}),
			wantUnit: S3SourceUnit{Bucket: "my-test-bucket"},
		},
		{
			name:     "envelope without unit_data, role-bearing, rebuilt from id",
			data:     marshalEnvelope(t, constructS3SourceUnitID("my-test-bucket", roleARN), "bucket", nil),
			wantUnit: S3SourceUnit{Bucket: "my-test-bucket", Role: roleARN},
		},
		{
			name:     "envelope without unit_data, role-less, rebuilt from id",
			data:     marshalEnvelope(t, constructS3SourceUnitID("my-test-bucket", ""), "bucket", nil),
			wantUnit: S3SourceUnit{Bucket: "my-test-bucket"},
		},
		{
			// A CommonSourceUnit-shaped bare unit from another source also has
			// an "id" field; only S3's own "bucket" kind may trigger the
			// envelope id-rebuild path, or this would be misread as a bucket.
			name:    "bare unit from another source is rejected, not misread as an envelope",
			data:    []byte(`{"kind":"repository","id":"some-repo-id"}`),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Source{}
			unit, err := s.UnmarshalSourceUnit(tt.data)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err, "UnmarshalSourceUnit should not return an error")

			s3Unit, ok := unit.(S3SourceUnit)
			require.True(t, ok, "Unmarshaled unit should be of type S3SourceUnit")
			assert.Equal(t, tt.wantUnit, s3Unit)
		})
	}
}

func TestSource_ObjectLink(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		want     string
	}{
		{
			name: "aws",
			want: "https://my-bucket.s3.eu-west-1.amazonaws.com/dir/key.txt",
		},
		{
			name:     "custom endpoint",
			endpoint: "https://s3.internal.example.com",
			want:     "https://s3.internal.example.com/my-bucket/dir/key.txt",
		},
		{
			name:     "custom endpoint with trailing slash",
			endpoint: "https://s3.internal.example.com/",
			want:     "https://s3.internal.example.com/my-bucket/dir/key.txt",
		},
		{
			name:     "custom endpoint with port and base path",
			endpoint: "http://minio.test:9000/base",
			want:     "http://minio.test:9000/base/my-bucket/dir/key.txt",
		},
		{
			name:     "endpoint without a scheme is assumed https",
			endpoint: "s3.internal.example.com",
			want:     "https://s3.internal.example.com/my-bucket/dir/key.txt",
		},
		{
			name:     "host and port without a scheme is assumed https",
			endpoint: "s3.internal.example.com:9000",
			want:     "https://s3.internal.example.com:9000/my-bucket/dir/key.txt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn, err := anypb.New(&sourcespb.S3{
				Credential: &sourcespb.S3_Unauthenticated{},
				Endpoint:   tt.endpoint,
			})
			require.NoError(t, err)

			s := Source{}
			require.NoError(t, s.Init(context.Background(), "s3 test source", 0, 0, false, conn, 1))

			assert.Equal(t, tt.want, s.objectLink("my-bucket", "eu-west-1", "dir/key.txt"))
		})
	}
}

func TestSource_Init_InvalidEndpoint(t *testing.T) {
	conn, err := anypb.New(&sourcespb.S3{
		Credential: &sourcespb.S3_Unauthenticated{},
		Endpoint:   "https://s3.internal.example.com:not-a-port",
	})
	require.NoError(t, err)

	s := Source{}
	assert.ErrorContains(t, s.Init(context.Background(), "s3 test source", 0, 0, false, conn, 1), "endpoint")
}

func TestSource_ClientAddressing(t *testing.T) {
	tests := []struct {
		name          string
		conn          *sourcespb.S3
		wantRegion    string
		wantEndpoint  *string
		wantPathStyle bool
	}{
		{
			name:       "aws defaults",
			conn:       &sourcespb.S3{},
			wantRegion: defaultAWSRegion,
		},
		{
			name:       "explicit region without endpoint",
			conn:       &sourcespb.S3{Region: "ap-south-1"},
			wantRegion: "ap-south-1",
		},
		{
			name:          "custom endpoint implies path style",
			conn:          &sourcespb.S3{Endpoint: "https://s3.internal.example.com"},
			wantRegion:    defaultAWSRegion,
			wantEndpoint:  aws.String("https://s3.internal.example.com"),
			wantPathStyle: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.conn.Credential = &sourcespb.S3_Unauthenticated{}
			conn, err := anypb.New(tt.conn)
			require.NoError(t, err)

			s := Source{}
			require.NoError(t, s.Init(context.Background(), "s3 test source", 0, 0, false, conn, 1))

			client, err := s.newClient(context.Background(), s.defaultRegion(), "")
			require.NoError(t, err)

			opts := client.Options()
			assert.Equal(t, tt.wantRegion, opts.Region)
			assert.Equal(t, tt.wantEndpoint, opts.BaseEndpoint)
			assert.Equal(t, tt.wantPathStyle, opts.UsePathStyle)
		})
	}
}

func TestSource_Init_IncludeAndExcludeExtensionsError(t *testing.T) {
	conn, err := anypb.New(&sourcespb.S3{
		Credential:        &sourcespb.S3_Unauthenticated{},
		IncludeExtensions: []string{"tf"},
		ExcludeExtensions: []string{"zip"},
	})
	assert.NoError(t, err)

	s := Source{}
	err = s.Init(context.Background(), "s3 test source", 0, 0, false, conn, 1)

	assert.Error(t, err)
}

// Prefixes, unlike extensions and unlike buckets, accept an include list and an
// exclude list together.
func TestSource_Init_IncludeAndExcludePrefixesAllowed(t *testing.T) {
	conn, err := anypb.New(&sourcespb.S3{
		Credential:      &sourcespb.S3_Unauthenticated{},
		IncludePrefixes: []string{"src/"},
		ExcludePrefixes: []string{"src/vendor/"},
	})
	assert.NoError(t, err)

	s := Source{}
	err = s.Init(context.Background(), "s3 test source", 0, 0, false, conn, 1)

	assert.NoError(t, err)
	assert.True(t, s.objectFilter.shouldInclude("src/main.tf"))
	assert.False(t, s.objectFilter.shouldInclude("src/vendor/dep.tf"))
}

// A source with no filters configured must scan every object, so that existing
// scans behave exactly as they did before object filtering was added.
func TestSource_Init_UnconfiguredFilterScansEverything(t *testing.T) {
	conn, err := anypb.New(&sourcespb.S3{Credential: &sourcespb.S3_Unauthenticated{}})
	assert.NoError(t, err)

	s := Source{}
	err = s.Init(context.Background(), "s3 test source", 0, 0, false, conn, 1)

	assert.NoError(t, err)
	assert.True(t, s.objectFilter.shouldInclude("any/key.zip"))
}

// A filtered object must still be marked complete on the checkpointer. Otherwise
// the low water mark stalls at the first filtered object and a resumed scan redoes
// every object after it.
func TestSource_PageChunker_FilteredObjectsAdvanceCheckpoint(t *testing.T) {
	ctx := context.Background()

	conn, err := anypb.New(&sourcespb.S3{
		Credential:      &sourcespb.S3_Unauthenticated{},
		ExcludePrefixes: []string{"archive/"},
	})
	require.NoError(t, err)

	s := Source{}
	require.NoError(t, s.Init(ctx, "s3 test source", 0, 0, false, conn, 1))

	const objectCount = 10
	page := &awss3.ListObjectsV2Output{Contents: make([]s3types.Object, objectCount)}
	for i := range objectCount {
		key := fmt.Sprintf("archive/key-%02d.txt", i)
		size := int64(1024)
		page.Contents[i] = s3types.Object{Key: &key, Size: &size}
	}

	checkpointer := NewCheckpointer(ctx, &sources.Progress{}, false)

	// Every object is filtered, so pageChunker never reaches GetObject and needs
	// no client.
	var scanned, filtered uint64
	s.pageChunker(
		ctx,
		pageMetadata{bucket: "test-bucket", pageNumber: 1, page: page},
		processingState{errorCount: &sync.Map{}, objectCount: &scanned, filteredCount: &filtered},
		sources.ChanReporter{Ch: make(chan *sources.Chunk, objectCount)},
		checkpointer,
	)

	assert.Zero(t, scanned)
	assert.EqualValues(t, objectCount, filtered)

	resumeInfo, err := checkpointer.ResumePoint(ctx)
	require.NoError(t, err)
	assert.Equal(t, "test-bucket", resumeInfo.CurrentBucket)
	assert.Equal(t, *page.Contents[objectCount-1].Key, resumeInfo.StartAfter)
}
