package gcs

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
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

func (m *mockObjectManager) listObjects(context.Context) (chan BinaryReader, error) {
	ch := make(chan BinaryReader)
	defer close(ch)

	if m.wantErr {
		return nil, fmt.Errorf("some error")
	}

	// Add 5 objects to the channel.
	for i := 0; i < 5; i++ {
		ch <- &object{
			name:        fmt.Sprintf("object%d", i),
			bucket:      testBucket,
			contentType: "plain/text",
			owner:       "testman@test.com",
			link:        fmt.Sprintf("https://storage.googleapis.com/%s/%s", testBucket, fmt.Sprintf("object%d", i)),
			acl:         []string{"authenticatedUsers"},
			size:        42,
			Reader:      &mockReader{},
		}
	}

	return ch, nil
}

func TestSourceChunks_ListObjects(t *testing.T) {
	ctx := context.Background()
	source := &Source{gcsManager: &mockObjectManager{}}

	chunksCh := make(chan *sources.Chunk, 1)

	go func() {
		defer close(chunksCh)
		err := source.Chunks(ctx, chunksCh)
		assert.Nil(t, err)
	}()

	// Ensure we get 5 objects back.
	count := 0
	for ch := range chunksCh {
		fmt.Printf("chunk: %v", ch)
		count++
	}
	assert.Equal(t, 5, count)
}

func TestSourceChunks_ListObjectsError(t *testing.T) {
	ctx := context.Background()
	source := &Source{gcsManager: &mockObjectManager{}}

	chunksCh := make(chan *sources.Chunk, 1)

	defer close(chunksCh)
	err := source.Chunks(ctx, chunksCh)
	assert.True(t, err != nil)
}
