//go:build integration

package docker

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/credentialspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

func TestDockerImageScan(t *testing.T) {
	dockerConn := &sourcespb.Docker{
		Credential: &sourcespb.Docker_Unauthenticated{
			Unauthenticated: &credentialspb.Unauthenticated{},
		},
		Images: []string{"trufflesecurity/secrets"},
	}

	conn := &anypb.Any{}
	err := conn.MarshalFrom(dockerConn)
	assert.NoError(t, err)

	s := &Source{}
	err = s.Init(context.TODO(), "test source", 0, 0, false, conn, 1)
	assert.NoError(t, err)

	var wg sync.WaitGroup
	chunksChan := make(chan *sources.Chunk, 1)
	chunkCounter := 0
	wg.Add(1)
	go func() {
		defer wg.Done()
		for chunk := range chunksChan {
			assert.NotEmpty(t, chunk)
			chunkCounter++
		}
	}()

	err = s.Chunks(context.TODO(), chunksChan)
	assert.NoError(t, err)

	close(chunksChan)
	wg.Wait()

	assert.Equal(t, 1, chunkCounter)
}
