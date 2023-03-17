package gcs

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

func createTestSource(src *sourcespb.GCS) (*Source, *anypb.Any) {
	s := &Source{}
	conn, err := anypb.New(src)
	if err != nil {
		panic(err)
	}
	return s, conn
}

func TestSourceInit(t *testing.T) {
	source, conn := createTestSource(&sourcespb.GCS{
		ProjectId: testProjectID,
		IncludeBuckets: []string{
			"bucket1",
		},
		ExcludeBuckets: []string{
			perfTestBucketGlob,
		},
		ExcludeObjects: []string{
			"object1",
		},
		Credential: &sourcespb.GCS_ApiKey{
			ApiKey: testAPIKey,
		},
	})

	// Set the EncodeResumeInfo to prevent enumeration.
	b, err := json.Marshal(map[string]objectsProgress{"other": {}})
	assert.Nil(t, err)
	source.Progress.EncodedResumeInfo = string(b)

	err = source.Init(context.Background(), "test", 1, 1, true, conn, 8)
	assert.Nil(t, err)
	assert.NotNil(t, source.gcsManager)
}

func TestSourceInit_Conn(t *testing.T) {
	testCases := []struct {
		name    string
		conn    *sourcespb.GCS
		want    *gcsManager
		wantErr bool
	}{
		{
			name:    "nil conn",
			wantErr: true,
		},
		{
			name: "valid conn, bare config",
			conn: &sourcespb.GCS{
				ProjectId:  testProjectID,
				Credential: &sourcespb.GCS_Adc{},
				ExcludeBuckets: []string{
					perfTestBucketGlob,
				},
			},
			want: &gcsManager{
				projectID:      testProjectID,
				excludeBuckets: map[string]struct{}{perfTestBucketGlob: {}},
				hasEnumerated:  true,
			},
		},
		{
			name: "valid conn, include and exclude buckets",
			conn: &sourcespb.GCS{
				ProjectId:  testProjectID,
				Credential: &sourcespb.GCS_Adc{},
				IncludeBuckets: []string{
					"bucket1",
				},
				ExcludeBuckets: []string{
					perfTestBucketGlob,
				},
			},
			want: &gcsManager{
				projectID:      testProjectID,
				includeBuckets: map[string]struct{}{"bucket1": {}},
				hasEnumerated:  true,
			},
		},
		{
			name: "valid conn, include and exclude objects",
			conn: &sourcespb.GCS{
				ProjectId:  testProjectID,
				Credential: &sourcespb.GCS_Adc{},
				IncludeObjects: []string{
					"object1",
				},
				ExcludeObjects: []string{
					"object2",
				},
				ExcludeBuckets: []string{
					perfTestBucketGlob,
				},
			},
			want: &gcsManager{
				projectID:      testProjectID,
				includeObjects: map[string]struct{}{"object1": {}},
				excludeBuckets: map[string]struct{}{perfTestBucketGlob: {}},
				hasEnumerated:  true,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			source, conn := createTestSource(tc.conn)
			// Set the EncodeResumeInfo to prevent enumeration.
			b, err := json.Marshal(map[string]objectsProgress{"other": {}})
			assert.Nil(t, err)
			source.Progress.EncodedResumeInfo = string(b)

			err = source.Init(context.Background(), "test", 1, 1, true, conn, 8)
			if err != nil && !tc.wantErr {
				t.Errorf("source.Init() got: %v, want: %v", err, nil)
				return
			}

			if !tc.wantErr {
				if diff := cmp.Diff(tc.want, source.gcsManager,
					cmp.AllowUnexported(gcsManager{}),
					cmpopts.IgnoreFields(gcsManager{}, "client", "workerPool", "concurrency", "buckets", "maxObjectSize", "attr"),
				); diff != "" {
					t.Errorf("source.Init() diff: (-want +got)\n%s", diff)
				}
			}
		})
	}
}

func TestSourceInit_Progress(t *testing.T) {
	complete := map[string]objectsProgress{testBucket: {
		Processed:         object2,
		IsBucketProcessed: true,
		ProcessedCnt:      1,
		TotalCnt:          1,
	}}
	completeEncodeResumeInfo, err := json.Marshal(complete)
	assert.Nil(t, err)

	processing := map[string]objectsProgress{
		testBucket: {
			IsBucketProcessed: false,
			ProcessedCnt:      1,
			Processed:         object2,
			Processing:        map[string]struct{}{object1: {}},
			TotalCnt:          2,
		},
	}
	processingEncodeResumeInfo, err := json.Marshal(processing)
	assert.Nil(t, err)

	testCases := []struct {
		name              string
		conn              *sourcespb.GCS
		encodeResumeInfo  string
		gcsManagerBuckets map[string]bucket
	}{
		{
			name:              "no progress",
			conn:              &sourcespb.GCS{ProjectId: testProjectID, Credential: &sourcespb.GCS_Adc{}, ExcludeBuckets: []string{perfTestBucketGlob}},
			gcsManagerBuckets: map[string]bucket{},
		},
		{
			name:              "progress set, no processing objects in any buckets",
			conn:              &sourcespb.GCS{ProjectId: testProjectID, Credential: &sourcespb.GCS_Adc{}},
			encodeResumeInfo:  string(completeEncodeResumeInfo),
			gcsManagerBuckets: map[string]bucket{testBucket: {name: testBucket, startOffset: "", shouldInclude: false}},
		},
		{
			name:              "progress set, processing objects in some buckets",
			conn:              &sourcespb.GCS{ProjectId: testProjectID, Credential: &sourcespb.GCS_Adc{}},
			encodeResumeInfo:  string(processingEncodeResumeInfo),
			gcsManagerBuckets: map[string]bucket{testBucket: {name: testBucket, startOffset: object1, shouldInclude: true}},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			source, conn := createTestSource(tc.conn)
			source.Progress.EncodedResumeInfo = tc.encodeResumeInfo

			err := source.Init(context.Background(), "test", 1, 1, true, conn, 8)
			assert.Nil(t, err)
			assert.Equal(t, tc.gcsManagerBuckets, source.gcsManager.(*gcsManager).buckets)
		})
	}
}

type mockObjectManager struct {
	wantErr bool
}

func (m *mockObjectManager) attributes(_ context.Context) (*attributes, error) {
	if m.wantErr {
		return nil, fmt.Errorf("some error")
	}

	return &attributes{
		numObjects:    5,
		numBuckets:    1,
		bucketObjects: map[string]uint64{testBucket: 5},
	}, nil
}

type mockReader struct {
	offset int
	data   []byte
}

func (m *mockReader) Read(p []byte) (n int, err error) {
	if m.offset >= len(m.data) {
		return 0, io.EOF
	}

	n = copy(p, m.data[m.offset:])
	m.offset += n
	return
}

func (m *mockObjectManager) listObjects(context.Context) (chan io.Reader, error) {
	if m.wantErr {
		return nil, fmt.Errorf("some error")
	}

	ch := make(chan io.Reader)
	go func() {
		defer close(ch)
		// Add 5 objects to the channel.
		for i := 0; i < 5; i++ {
			ch <- createTestObject(i)
		}
	}()

	return ch, nil
}

func createTestObject(id int) object {
	return object{
		name:        fmt.Sprintf("object%d", id),
		bucket:      testBucket,
		contentType: "plain/text",
		owner:       "testman@test.com",
		link:        fmt.Sprintf("https://storage.googleapis.com/%s/%s", testBucket, fmt.Sprintf("object%d", id)),
		acl:         []string{"authenticatedUsers"},
		size:        42,
		Reader:      &mockReader{data: []byte(fmt.Sprintf("hello world %d", id))},
	}
}

func createTestSourceChunk(id int) *sources.Chunk {
	return &sources.Chunk{
		SourceName: "test",
		SourceType: sourcespb.SourceType_SOURCE_TYPE_GCS,
		SourceID:   0,
		Verify:     true,
		Data:       []byte(fmt.Sprintf("hello world %d", id)),
		SourceMetadata: &source_metadatapb.MetaData{
			Data: &source_metadatapb.MetaData_Gcs{
				Gcs: &source_metadatapb.GCS{
					Filename:    fmt.Sprintf("object%d", id),
					Bucket:      testBucket,
					ContentType: "plain/text",
					Email:       "testman@test.com",
					Link:        fmt.Sprintf("https://storage.googleapis.com/%s/%s", testBucket, fmt.Sprintf("object%d", id)),
					Acls:        []string{"authenticatedUsers"},
				},
			},
		},
	}
}

func TestSourceChunks_ListObjects(t *testing.T) {
	ctx := context.Background()
	chunksCh := make(chan *sources.Chunk, 1)

	source := &Source{
		gcsManager: &mockObjectManager{},
		chunksCh:   chunksCh,
	}

	err := source.enumerate(ctx)
	assert.Nil(t, err)

	go func() {
		defer close(chunksCh)
		err := source.Chunks(ctx, chunksCh)
		assert.Nil(t, err)
	}()

	want := make([]*sources.Chunk, 0, 5)
	for i := 0; i < 5; i++ {
		want = append(want, createTestSourceChunk(i))
	}

	count := 0
	got := make([]*sources.Chunk, 0, 5)
	for ch := range chunksCh {
		got = append(got, ch)
		count++
	}

	// Ensure we get 5 objects back.
	assert.Equal(t, 5, count)

	// Sort the results to ensure deterministic ordering.
	sort.Slice(want, func(i, j int) bool {
		return want[i].SourceMetadata.GetGcs().Filename < want[j].SourceMetadata.GetGcs().Filename
	})
	sort.Slice(got, func(i, j int) bool {
		return got[i].SourceMetadata.GetGcs().Filename < got[j].SourceMetadata.GetGcs().Filename
	})

	for _, c := range got {
		assert.Equal(t, c.SourceMetadata.GetGcs().Filename, c.SourceMetadata.GetGcs().Filename)
		assert.Equal(t, c.Data, c.Data)
	}

}

func TestSourceInit_Enumerate(t *testing.T) {
	ctx := context.Background()
	source := &Source{gcsManager: &mockObjectManager{}}

	err := source.enumerate(ctx)
	assert.Nil(t, err)

	// Ensure the attributes are set.
	assert.Equal(t, uint64(5), source.stats.numObjects)
	assert.Equal(t, uint32(1), source.stats.numBuckets)
	assert.Equal(t, uint64(5), source.stats.bucketObjects[testBucket])
	// Ensure progress is initialized correctly.
	p := map[string]*objectsProgress{testBucket: {IsBucketProcessed: false, ProcessedCnt: 0, TotalCnt: 5}}
	b, err := json.Marshal(p)
	assert.Nil(t, err)
	assert.Equal(t, string(b), source.Progress.EncodedResumeInfo)
}

func TestSourceChunks_ListObjects_Error(t *testing.T) {
	ctx := context.Background()
	source := &Source{gcsManager: &mockObjectManager{wantErr: true}}

	chunksCh := make(chan *sources.Chunk, 1)

	defer close(chunksCh)
	err := source.Chunks(ctx, chunksCh)
	assert.True(t, err != nil)
}

func TestSourceChunks_ProgressSet(t *testing.T) {
	ctx := context.Background()
	chunksCh := make(chan *sources.Chunk, 1)

	source := &Source{
		gcsManager: &mockObjectManager{},
		chunksCh:   chunksCh,
	}
	err := source.enumerate(ctx)
	assert.Nil(t, err)

	go func() {
		defer close(chunksCh)
		err := source.Chunks(ctx, chunksCh)
		assert.Nil(t, err)
	}()

	want := make([]*sources.Chunk, 0, 5)
	for i := 0; i < 5; i++ {
		want = append(want, createTestSourceChunk(i))
	}

	got := make([]*sources.Chunk, 0, 5)
	for ch := range chunksCh {
		got = append(got, ch)
	}

	// Ensure we get 5 objects back.
	assert.Equal(t, len(want), len(got))

	processing := map[string]struct{}{"object0": {}, "object1": {}, "object2": {}, "object3": {}, "object4": {}}
	for i := 0; i < 5; i++ {
		delete(processing, fmt.Sprintf("object%d", i))
	}

	// Test that the resume progress is set.
	// The processed values should be the greatest object name lexicographically.
	resume := map[string]objectsProgress{
		testBucket: {
			Processed:         "object4",
			Processing:        processing,
			IsBucketProcessed: true,
			ProcessedCnt:      5,
			TotalCnt:          5,
		},
	}
	b, err := json.Marshal(resume)
	assert.Nil(t, err)

	assert.Equal(t, string(b), source.Progress.EncodedResumeInfo)
	assert.Equal(t, int32(5), source.Progress.SectionsCompleted)
	assert.Equal(t, int64(100), source.Progress.PercentComplete)
}
