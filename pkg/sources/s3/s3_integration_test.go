//go:build integration
// +build integration

package s3

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

func TestSource_ChunksCount(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()

	s := Source{}
	connection := &sourcespb.S3{
		Credential: &sourcespb.S3_Unauthenticated{},
		Buckets:    []string{"truffletestbucket"},
	}
	conn, err := anypb.New(connection)
	if err != nil {
		t.Fatal(err)
	}

	err = s.Init(ctx, "test name", 0, 0, false, conn, 1)
	chunksCh := make(chan *sources.Chunk)
	go func() {
		defer close(chunksCh)
		err = s.Chunks(ctx, chunksCh)
		assert.Nil(t, err)
	}()

	wantChunkCount := 120
	got := 0

	for range chunksCh {
		got++
	}
	assert.Greater(t, got, wantChunkCount)
}
