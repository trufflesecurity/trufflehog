package s3

import (
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/go-logr/logr/funcr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sourcestest"
)

func TestSource_ListInputs(t *testing.T) {
	startAfter := "infra/main.tf"

	tests := []struct {
		name         string
		bucket       string
		prefixes     []string
		wantPrefixes []string
	}{
		{name: "no include prefixes", bucket: "bucket", wantPrefixes: []string{""}},
		{
			name:         "one listing per include prefix, in key order",
			bucket:       "bucket",
			prefixes:     []string{"src/", "infra/"},
			wantPrefixes: []string{"infra/", "src/"},
		},
		{
			name:         "directory bucket",
			bucket:       "data--usw2-az1--x-s3",
			prefixes:     []string{"src"},
			wantPrefixes: []string{""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Source{objectFilter: newTestObjectFilter(t, tt.prefixes, nil, nil, nil)}

			var gotPrefixes []string
			for _, input := range s.listInputs(tt.bucket, &startAfter) {
				assert.Equal(t, tt.bucket, aws.ToString(input.Bucket))
				assert.Equal(t, startAfter, aws.ToString(input.StartAfter), "every listing resumes at the checkpoint")
				gotPrefixes = append(gotPrefixes, aws.ToString(input.Prefix))
			}
			assert.Equal(t, tt.wantPrefixes, gotPrefixes)
		})
	}
}

// prefixTestObjects has keys under the include prefixes the tests below use, one of them nested in
// another, and keys between and around them that no include prefix covers.
func prefixTestObjects() map[string]string {
	objects := make(map[string]string)
	for _, key := range []string{
		"configs/app.yaml",
		"infra/main.tf", "infra/vars.tf",
		"logs/1.log", "logs/2.log", "logs/3.log", "logs/4.log",
		"src/main.go", "src/vendor/dep.go",
		"tests/main_test.go",
	} {
		objects[key] = "contents of " + key
	}
	return objects
}

func withIncludePrefixes(prefixes ...string) func(*sourcespb.S3) {
	return func(conn *sourcespb.S3) { conn.IncludePrefixes = prefixes }
}

// scannedKeys counts the chunks reported for each object.
func scannedKeys(chunks []sources.Chunk) map[string]int {
	keys := make(map[string]int)
	for _, chunk := range chunks {
		keys[chunk.SourceMetadata.GetS3().GetFile()]++
	}
	return keys
}

func TestSource_ChunkUnit_ListsOnlyIncludePrefixes(t *testing.T) {
	fake := &fakeS3{buckets: map[string]fakeBucket{"bucket": {objects: prefixTestObjects()}}}
	s := newFakeS3Source(t, fake, withIncludePrefixes("src/", "infra/", "src/vendor/"))

	reporter := sourcestest.TestReporter{}
	require.NoError(t, s.ChunkUnit(context.Background(), S3SourceUnit{Bucket: "bucket"}, &reporter))

	want := map[string]int{"infra/main.tf": 1, "infra/vars.tf": 1, "src/main.go": 1, "src/vendor/dep.go": 1}
	assert.Equal(t, want, scannedKeys(reporter.Chunks), "each object under a prefix is scanned once")
	// infra/ and src/ fit a page each, where listing the whole bucket takes six.
	assert.EqualValues(t, 2, fake.listCalls.Load())
}

// A checkpoint is the last key the scan finished, whether it lies under an include prefix or not, as
// one left by a scan that listed the whole bucket may.
func TestSource_ChunkUnit_ResumesAcrossIncludePrefixes(t *testing.T) {
	tests := []struct {
		name       string
		startAfter string
		want       []string
	}{
		{
			name:       "before every prefix",
			startAfter: "a",
			want:       []string{"infra/main.tf", "infra/vars.tf", "src/main.go", "src/vendor/dep.go"},
		},
		{
			name:       "within a prefix",
			startAfter: "infra/main.tf",
			want:       []string{"infra/vars.tf", "src/main.go", "src/vendor/dep.go"},
		},
		{name: "between prefixes", startAfter: "logs/3.log", want: []string{"src/main.go", "src/vendor/dep.go"}},
		{name: "before a nested prefix", startAfter: "src/main.go", want: []string{"src/vendor/dep.go"}},
		{name: "after every prefix", startAfter: "tests/main_test.go"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := &fakeS3{buckets: map[string]fakeBucket{"bucket": {objects: prefixTestObjects()}}}
			s := newFakeS3Source(t, fake, withIncludePrefixes("infra/", "src/", "src/vendor/"))

			unit := S3SourceUnit{Bucket: "bucket"}
			unitID, _ := unit.SourceUnitID()
			s.SetEncodedResumeInfoFor(unitID, tt.startAfter)

			reporter := sourcestest.TestReporter{}
			require.NoError(t, s.ChunkUnit(context.Background(), unit, &reporter))

			want := make(map[string]int)
			for _, key := range tt.want {
				want[key] = 1
			}
			assert.Equal(t, want, scannedKeys(reporter.Chunks))
		})
	}
}

// S3 applies the include prefixes itself, so a mistyped one leaves no object for the filter to
// exclude. The scan must still say it found nothing, or it looks like a clean scan of an empty bucket,
// but only when the prefixes truly listed nothing.
func TestSource_ChunkUnit_ReportsIncludePrefixesListingNothing(t *testing.T) {
	tests := []struct {
		name       string
		prefix     string
		startAfter string
		want       bool
	}{
		{name: "mistyped prefix", prefix: "infa/", want: true},
		{name: "resumed after every prefix", prefix: "infra/", startAfter: "infra/vars.tf"},
		{name: "listed objects the scan skips", prefix: "empty"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			objects := prefixTestObjects()
			objects["empty.txt"] = ""
			fake := &fakeS3{buckets: map[string]fakeBucket{"bucket": {objects: objects}}}
			s := newFakeS3Source(t, fake, withIncludePrefixes(tt.prefix))

			unit := S3SourceUnit{Bucket: "bucket"}
			unitID, _ := unit.SourceUnitID()
			s.SetEncodedResumeInfoFor(unitID, tt.startAfter)

			var mu sync.Mutex
			var logged []string
			ctx := context.WithLogger(context.Background(), funcr.New(func(_, args string) {
				mu.Lock()
				defer mu.Unlock()
				logged = append(logged, args)
			}, funcr.Options{}))

			require.NoError(t, s.ChunkUnit(ctx, unit, &sourcestest.TestReporter{}))

			assert.Equal(t, tt.want, slices.ContainsFunc(logged, func(line string) bool {
				return strings.Contains(line, "Found no objects under the include prefixes")
			}))
		})
	}
}

// A policy can allow listing some prefixes and not others, so a failed listing must say which.
func TestBucketPaginator_ErrorNamesPrefix(t *testing.T) {
	fake := &fakeS3{buckets: map[string]fakeBucket{"bucket": {objects: prefixTestObjects(), listPrefix: "infra/"}}}
	s := newFakeS3Source(t, fake, withIncludePrefixes("infra/", "src/"))
	client, err := s.newClient(context.Background(), s.defaultRegion(), "")
	require.NoError(t, err)

	paginator := newBucketPaginator(client, s.listInputs("bucket", nil))
	var listErr error
	for paginator.HasMorePages() && listErr == nil {
		_, listErr = paginator.NextPage(context.Background())
	}

	assert.ErrorContains(t, listErr, `could not list prefix "src/"`)
}

func TestSource_ChunkUnit_CountsOnlyIncludePrefixes(t *testing.T) {
	enableUnitProgress(t)
	fake := &fakeS3{buckets: map[string]fakeBucket{"bucket": {objects: prefixTestObjects()}}}
	s := newFakeS3Source(t, fake, withIncludePrefixes("infra/", "src/"))

	unit := S3SourceUnit{Bucket: "bucket"}
	require.NoError(t, s.ChunkUnit(context.Background(), unit, &sourcestest.TestReporter{}))

	unitID, _ := unit.SourceUnitID()
	got, _ := s.GetUnitProgressFor(unitID)
	assert.Equal(t, sources.UnitProgressReady, got.State)
	assert.EqualValues(t, 4, got.ItemsTotal)
	assert.EqualValues(t, 4, fake.listCalls.Load(), "the count lists the same two prefixes as the scan")
}

// A policy can limit listing to some prefixes. Validate must list the way the scan does, or it
// rejects access the scan has.
func TestSource_Validate_ListsIncludePrefix(t *testing.T) {
	tests := []struct {
		name     string
		prefixes []string
		wantErr  bool
	}{
		{name: "whole bucket", wantErr: true},
		{name: "include prefix", prefixes: []string{"infra/"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := &fakeS3{buckets: map[string]fakeBucket{
				"bucket": {objects: prefixTestObjects(), listPrefix: "infra/"},
			}}
			s := newFakeS3Source(t, fake, withIncludePrefixes(tt.prefixes...), func(conn *sourcespb.S3) {
				conn.Buckets = []string{"bucket"}
			})

			errs := s.Validate(context.Background())

			if tt.wantErr {
				assert.NotEmpty(t, errs)
			} else {
				assert.Empty(t, errs)
			}
		})
	}
}
