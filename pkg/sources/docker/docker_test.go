package docker

import (
	"io"
	"strings"
	"sync"
	"testing"

	image "github.com/docker/docker/api/types/image"
	dockerClient "github.com/docker/docker/client"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/credentialspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
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
	layerCounter := 0
	historyCounter := 0

	wg.Add(1)
	go func() {
		defer wg.Done()
		for chunk := range chunksChan {
			assert.NotEmpty(t, chunk)
			chunkCounter++

			if isHistoryChunk(t, chunk) {
				historyCounter++
			} else {
				layerCounter++
			}
		}
	}()

	err = s.Chunks(context.TODO(), chunksChan)
	assert.NoError(t, err)

	close(chunksChan)
	wg.Wait()

	assert.Equal(t, 2, chunkCounter)
	assert.Equal(t, 1, layerCounter)
	assert.Equal(t, 1, historyCounter)
}

func TestDockerImageScanWithDigest(t *testing.T) {
	dockerConn := &sourcespb.Docker{
		Credential: &sourcespb.Docker_Unauthenticated{
			Unauthenticated: &credentialspb.Unauthenticated{},
		},
		Images: []string{"trufflesecurity/secrets@sha256:864f6d41209462d8e37fc302ba1532656e265f7c361f11e29fed6ca1f4208e11"},
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
	layerCounter := 0
	historyCounter := 0

	var historyChunk *source_metadatapb.Docker
	var layerChunk *source_metadatapb.Docker

	wg.Add(1)
	go func() {
		defer wg.Done()
		for chunk := range chunksChan {
			assert.NotEmpty(t, chunk)
			chunkCounter++

			if isHistoryChunk(t, chunk) {
				// save last for later comparison
				historyChunk = chunk.SourceMetadata.GetDocker()
				historyCounter++
			} else {
				layerChunk = chunk.SourceMetadata.GetDocker()
				layerCounter++
			}
		}
	}()

	err = s.Chunks(context.TODO(), chunksChan)
	assert.NoError(t, err)

	close(chunksChan)
	wg.Wait()

	// Since this test pins the layer by digest, layers will have consistent
	// hashes. This allows layer digest comparison as they will be stable for
	// given image digest.
	assert.Equal(t, &source_metadatapb.Docker{
		Image: "trufflesecurity/secrets",
		Tag:   "sha256:864f6d41209462d8e37fc302ba1532656e265f7c361f11e29fed6ca1f4208e11",
		File:  "image-metadata:history:0:created-by",
		Layer: "sha256:a794864de8c4ff087813fd66cff74601b84cbef8fe1a1f17f9923b40cf051b59",
	}, historyChunk)

	assert.Equal(t, &source_metadatapb.Docker{
		Image: "trufflesecurity/secrets",
		Tag:   "sha256:864f6d41209462d8e37fc302ba1532656e265f7c361f11e29fed6ca1f4208e11",
		File:  "/aws",
		Layer: "sha256:a794864de8c4ff087813fd66cff74601b84cbef8fe1a1f17f9923b40cf051b59",
	}, layerChunk)

	assert.Equal(t, 2, chunkCounter)
	assert.Equal(t, 1, layerCounter)
	assert.Equal(t, 1, historyCounter)
}

func TestDockerImageScanFromLocalDaemon(t *testing.T) {
	dockerDaemonTestCases := []struct {
		name  string
		image string
	}{
		{
			name:  "TestDockerImageScanFromLocalDaemon",
			image: "docker://trufflesecurity/secrets",
		},
		{
			name:  "TestDockerImageScanFromLocalDaemonWithDigest",
			image: "docker://trufflesecurity/secrets@sha256:864f6d41209462d8e37fc302ba1532656e265f7c361f11e29fed6ca1f4208e11",
		},
		{
			name:  "TestDockerImageScanFromLocalDaemonWithTag",
			image: "docker://trufflesecurity/secrets:latest",
		},
	}

	// pull the image here to ensure it exists locally
	img := "docker.io/trufflesecurity/secrets:latest"

	client, err := dockerClient.NewClientWithOpts(dockerClient.FromEnv, dockerClient.WithAPIVersionNegotiation())
	if err != nil {
		t.Errorf("Failed to create Docker client: %v", err)
		return
	}

	resp, err := client.ImagePull(context.TODO(), img, image.PullOptions{})
	if err != nil {
		t.Errorf("Failed to load image %s: %v", img, err)
		return
	}

	defer resp.Close()

	// if we don't read the response, the image will not be available in the local Docker daemon
	_, err = io.ReadAll(resp)
	if err != nil {
		t.Errorf("Failed to read response body: %v", err)
	}

	for _, tt := range dockerDaemonTestCases {
		t.Run(tt.name, func(t *testing.T) {
			// This test assumes the local Docker daemon is running
			dockerConn := &sourcespb.Docker{
				Credential: &sourcespb.Docker_Unauthenticated{
					Unauthenticated: &credentialspb.Unauthenticated{},
				},
				Images: []string{tt.image},
			}

			conn := &anypb.Any{}
			err = conn.MarshalFrom(dockerConn)
			assert.NoError(t, err)

			s := &Source{}
			err = s.Init(context.TODO(), "test source", 0, 0, false, conn, 1)
			assert.NoError(t, err)

			var wg sync.WaitGroup
			chunksChan := make(chan *sources.Chunk, 1)
			chunkCounter := 0
			layerCounter := 0
			historyCounter := 0

			wg.Add(1)
			go func() {
				defer wg.Done()
				for chunk := range chunksChan {
					assert.NotEmpty(t, chunk)
					chunkCounter++

					if isHistoryChunk(t, chunk) {
						historyCounter++
					} else {
						layerCounter++
					}
				}
			}()

			err = s.Chunks(context.TODO(), chunksChan)
			assert.NoError(t, err)

			close(chunksChan)
			wg.Wait()

			assert.Equal(t, 2, chunkCounter)
			assert.Equal(t, 1, layerCounter)
			assert.Equal(t, 1, historyCounter)
		})
	}
}

func TestBaseAndTagFromImage(t *testing.T) {
	tests := []struct {
		image      string
		wantBase   string
		wantTag    string
		wantDigest bool
	}{
		{"golang:1.16", "golang", "1.16", false},
		{"golang@sha256:abcdef", "golang", "sha256:abcdef", true},
		{"ghcr.io/golang:1.16", "ghcr.io/golang", "1.16", false},
		{"ghcr.io/golang:nightly", "ghcr.io/golang", "nightly", false},
		{"ghcr.io/golang", "ghcr.io/golang", "latest", false},
		{"ghcr.io/trufflesecurity/secrets", "ghcr.io/trufflesecurity/secrets", "latest", false},
	}

	for _, tt := range tests {
		gotBase, gotTag, gotDigest := baseAndTagFromImage(tt.image)
		if gotBase != tt.wantBase || gotTag != tt.wantTag || gotDigest != tt.wantDigest {
			t.Errorf("baseAndTagFromImage(%q) = (%q, %q, %v), want (%q, %q, %v)",
				tt.image, gotBase, gotTag, gotDigest, tt.wantBase, tt.wantTag, tt.wantDigest)
		}
	}
}

func isHistoryChunk(t *testing.T, chunk *sources.Chunk) bool {
	t.Helper()

	metadata := chunk.SourceMetadata.GetDocker()

	return metadata != nil &&
		strings.HasPrefix(metadata.File, "image-metadata:history:")
}

func TestDockerScanWithExclusions(t *testing.T) {
	dockerConn := &sourcespb.Docker{
		Credential: &sourcespb.Docker_Unauthenticated{
			Unauthenticated: &credentialspb.Unauthenticated{},
		},
		Images:       []string{"trufflesecurity/secrets@sha256:864f6d41209462d8e37fc302ba1532656e265f7c361f11e29fed6ca1f4208e11"},
		ExcludePaths: []string{"/aws", "/gcp*", "/exactmatch"},
	}

	conn := &anypb.Any{}
	err := conn.MarshalFrom(dockerConn)
	assert.NoError(t, err)

	s := &Source{}
	err = s.Init(context.TODO(), "test source", 0, 0, false, conn, 1)
	assert.NoError(t, err)

	// Test cases for exclusion logic
	testCases := []struct {
		name     string
		path     string
		expected bool
	}{
		{"excluded_exact", "/aws", true},
		{"excluded_wildcard", "/gcp/something", true},
		{"excluded_exact_match_file", "/exactmatch", true},
		{"not_excluded", "/azure", false},
		{"gcp_root_should_be_excluded_by_gcp_star", "/gcp", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, s.isExcluded(context.TODO(), tc.path))
		})
	}

	// Keep the original test structure to ensure Chunks processing respects exclusions
	var wg sync.WaitGroup
	chunksChan := make(chan *sources.Chunk, 1)
	foundExcludedPath := false

	wg.Add(1)
	go func() {
		defer wg.Done()
		for chunk := range chunksChan {
			// Skip history chunks
			if isHistoryChunk(t, chunk) {
				continue
			}

			metadata := chunk.SourceMetadata.GetDocker()
			assert.NotNil(t, metadata)

			// Check if we found a chunk with the excluded path
			if metadata.File == "/aws" {
				foundExcludedPath = true
			}
		}
	}()

	err = s.Chunks(context.TODO(), chunksChan)
	assert.NoError(t, err)

	close(chunksChan)
	wg.Wait()

	assert.False(t, foundExcludedPath, "Found a chunk that should have been excluded")
}
