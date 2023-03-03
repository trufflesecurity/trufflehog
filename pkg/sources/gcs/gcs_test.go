package gcs

import (
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sync/errgroup"
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
		ExcludeObjects: []string{
			"object1",
		},
		Credential: &sourcespb.GCS_ApiKey{
			ApiKey: testAPIKey,
		},
	})

	err := source.Init(context.Background(), "test", 1, 1, true, conn, 8)
	assert.Nil(t, err)
	assert.NotNil(t, source.gcsManager)
}

type mockObjectManager struct {
	wantErr bool
}

type mockReader struct{}

func (m *mockReader) Read(_ []byte) (n int, err error) {
	return 0, nil
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
		// acl:         []string{"authenticatedUsers"},
		size:   42,
		Reader: &mockReader{},
	}
}

func createTestSourceChunk(id int) *sources.Chunk {
	return &sources.Chunk{
		SourceName: "test",
		SourceType: sourcespb.SourceType_SOURCE_TYPE_GCS,
		SourceID:   0,
		Verify:     true,
		SourceMetadata: &source_metadatapb.MetaData{
			Data: &source_metadatapb.MetaData_Gcs{
				Gcs: &source_metadatapb.GCS{
					Filename: fmt.Sprintf("object%d", id),
					Bucket:   testBucket,
					// ContentType: "plain/text",
					Email: "testman@test.com",
					Link:  fmt.Sprintf("https://storage.googleapis.com/%s/%s", testBucket, fmt.Sprintf("object%d", id)),
					// Acl:         []string{"authenticatedUsers"},
					// Size:        42,
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
		jobPool:    new(errgroup.Group),
		chunksCh:   chunksCh,
	}

	go func() {
		defer close(chunksCh)
		err := source.Chunks(ctx, chunksCh)
		assert.Nil(t, err)
	}()

	res := make([]*sources.Chunk, 0, 5)
	for i := 0; i < 5; i++ {
		res = append(res, createTestSourceChunk(i))
	}

	// Ensure we get 5 objects back.
	count := 0

	for ch := range chunksCh {
		assert.Equal(
			t, res[count].SourceMetadata.Data.(*source_metadatapb.MetaData_Gcs).Gcs.Filename,
			ch.SourceMetadata.Data.(*source_metadatapb.MetaData_Gcs).Gcs.Filename,
		)
		count++
	}
	assert.Equal(t, 5, count)
}

func TestSourceChunks_ListObjects_Error(t *testing.T) {
	ctx := context.Background()
	source := &Source{gcsManager: &mockObjectManager{}}

	chunksCh := make(chan *sources.Chunk, 1)

	defer close(chunksCh)
	err := source.Chunks(ctx, chunksCh)
	assert.True(t, err != nil)
}
