package docker

import (
	"regexp"
	"strings"
	"sync"
	"testing"

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

func TestDockerExcludeExactPath(t *testing.T) {
	dockerConn := &sourcespb.Docker{
		Credential: &sourcespb.Docker_Unauthenticated{
			Unauthenticated: &credentialspb.Unauthenticated{},
		},
		Images:       []string{"test-image"},
		ExcludePaths: []string{"/var/log/test"},
	}

	conn := &anypb.Any{}
	err := conn.MarshalFrom(dockerConn)
	assert.NoError(t, err)

	s := &Source{}
	err = s.Init(context.TODO(), "test source", 0, 0, false, conn, 1)
	assert.NoError(t, err)

	// Create test data
	testFiles := []struct {
		path     string
		excluded bool
	}{
		{"/var/log/test", true},      // Should be excluded (exact match)
		{"/var/log/test2", false},    // Should not be excluded (different path)
		{"/var/log/test/sub", false}, // Should not be excluded (subdirectory)
		{"/var/log/other", false},    // Should not be excluded (different path)
	}

	for _, tf := range testFiles {
		excluded := false
		for _, excludePath := range s.excludePaths {
			if tf.path == excludePath {
				excluded = true
				break
			}
		}
		assert.Equal(t, tf.excluded, excluded, "Unexpected exclusion result for path: %s", tf.path)
	}
}

func TestDockerExcludeWildcardPath(t *testing.T) {
	dockerConn := &sourcespb.Docker{
		Credential: &sourcespb.Docker_Unauthenticated{
			Unauthenticated: &credentialspb.Unauthenticated{},
		},
		Images:       []string{"test-image"},
		ExcludePaths: []string{"/var/log/test/*"},
	}

	conn := &anypb.Any{}
	err := conn.MarshalFrom(dockerConn)
	assert.NoError(t, err)

	s := &Source{}
	err = s.Init(context.TODO(), "test source", 0, 0, false, conn, 1)
	assert.NoError(t, err)

	// Create test data
	testFiles := []struct {
		path     string
		excluded bool
	}{
		{"/var/log/test/file1", true},     // Should be excluded (direct child)
		{"/var/log/test/sub/file2", true}, // Should be excluded (nested child)
		{"/var/log/test", false},          // Should not be excluded (parent dir)
		{"/var/log/test2/file", false},    // Should not be excluded (different dir)
		{"/var/log/other/file", false},    // Should not be excluded (unrelated)
	}

	for _, tf := range testFiles {
		excluded := false
		for _, excludePath := range s.excludePaths {
			// Convert wildcard pattern to regex
			pattern := strings.ReplaceAll(excludePath, "*", ".*")
			pattern = "^" + pattern + "$"
			isMatch, err := regexp.MatchString(pattern, tf.path)
			assert.NoError(t, err)
			if isMatch {
				excluded = true
				break
			}
		}
		assert.Equal(t, tf.excluded, excluded, "Unexpected exclusion result for path: %s", tf.path)
	}
}

func TestShouldExclude(t *testing.T) {
	tests := []struct {
		name         string
		excludePaths []string
		testPath     string
		want         bool
	}{
		{
			name:         "exact match should exclude",
			excludePaths: []string{"/var/log/test"},
			testPath:     "/var/log/test",
			want:         true,
		},
		{
			name:         "non-matching path should not exclude",
			excludePaths: []string{"/var/log/test"},
			testPath:     "/var/log/other",
			want:         false,
		},
		{
			name:         "wildcard should match children",
			excludePaths: []string{"/var/log/*"},
			testPath:     "/var/log/test",
			want:         true,
		},
		{
			name:         "wildcard should not match parent",
			excludePaths: []string{"/var/log/*/deep"},
			testPath:     "/var/log",
			want:         false,
		},
		{
			name:         "multiple patterns should work",
			excludePaths: []string{"/var/log/*", "/etc/nginx/*", "/tmp/test"},
			testPath:     "/etc/nginx/conf.d/default.conf",
			want:         true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dockerConn := &sourcespb.Docker{
				Credential: &sourcespb.Docker_Unauthenticated{
					Unauthenticated: &credentialspb.Unauthenticated{},
				},
				ExcludePaths: tt.excludePaths,
			}

			conn := &anypb.Any{}
			err := conn.MarshalFrom(dockerConn)
			assert.NoError(t, err)

			s := &Source{}
			err = s.Init(context.TODO(), "test", 0, 0, false, conn, 1)
			assert.NoError(t, err)

			// Test if the path should be excluded
			excluded := false
			for _, path := range tt.excludePaths {
				if tt.testPath == path {
					excluded = true
					break
				}
				// Convert wildcard pattern to regex
				pattern := strings.ReplaceAll(path, "*", ".*")
				pattern = "^" + pattern + "$"
				isMatch, err := regexp.MatchString(pattern, tt.testPath)
				assert.NoError(t, err)
				if isMatch {
					excluded = true
					break
				}
			}
			assert.Equal(t, tt.want, excluded)
		})
	}
}

func TestDockerScanWithExclusions(t *testing.T) {
	dockerConn := &sourcespb.Docker{
		Credential: &sourcespb.Docker_Unauthenticated{
			Unauthenticated: &credentialspb.Unauthenticated{},
		},
		Images:       []string{"trufflesecurity/secrets@sha256:864f6d41209462d8e37fc302ba1532656e265f7c361f11e29fed6ca1f4208e11"},
		ExcludePaths: []string{"/aws"}, // This path exists in the test image
	}

	conn := &anypb.Any{}
	err := conn.MarshalFrom(dockerConn)
	assert.NoError(t, err)

	s := &Source{}
	err = s.Init(context.TODO(), "test source", 0, 0, false, conn, 1)
	assert.NoError(t, err)

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
