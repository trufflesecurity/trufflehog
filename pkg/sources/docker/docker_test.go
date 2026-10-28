package docker

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	stdlog "log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/go-logr/zapr"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	dockerClient "github.com/moby/moby/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/log/logtest"
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

func TestQuayRegistry(t *testing.T) {
	dockerConn := &sourcespb.Docker{
		Credential: &sourcespb.Docker_Unauthenticated{
			Unauthenticated: &credentialspb.Unauthenticated{},
		},
		Images: []string{"quay.io/prometheus/node-exporter@sha256:337ff1d356b68d39cef853e8c6345de11ce7556bb34cda8bd205bcf2ed30b565"},
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

	assert.Equal(t, 1302, chunkCounter)
	assert.Equal(t, 1291, layerCounter)
	assert.Equal(t, 11, historyCounter)
}

func TestGHCRRegistry(t *testing.T) {
	dockerConn := &sourcespb.Docker{
		Credential: &sourcespb.Docker_Unauthenticated{
			Unauthenticated: &credentialspb.Unauthenticated{},
		},
		Images: []string{"ghcr.io/trufflesecurity/trufflehog:3.0.0-rc0-amd64"}, // https://github.com/trufflesecurity/trufflehog/pkgs/container/trufflehog
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

	assert.Equal(t, 714, chunkCounter)
	assert.Equal(t, 709, layerCounter)
	assert.Equal(t, 5, historyCounter)
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

	client, err := dockerClient.New(dockerClient.FromEnv)
	if err != nil {
		t.Errorf("Failed to create Docker client: %v", err)
		return
	}

	resp, err := client.ImagePull(context.TODO(), img, dockerClient.ImagePullOptions{})
	if err != nil {
		t.Errorf("Failed to load image %s: %v", img, err)
		return
	}

	defer func() { _ = resp.Close() }()

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

func TestSource_DebugLogging(t *testing.T) {
	const testSecret = "dockerdebuglogtestsecret"

	// newFakeRegistry pushes an image with one layer holding a secret file and an
	// excluded file. After the push, the first manifest GET fails with a 503, so
	// the scan has to retry it.
	newFakeRegistry := func(t *testing.T) string {
		var tarBuf bytes.Buffer
		tw := tar.NewWriter(&tarBuf)
		for name, content := range map[string]string{
			"secret.txt":  "token=" + testSecret,
			"skip/me.txt": "nothing to see",
		} {
			require.NoError(t, tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(content))}))
			_, err := tw.Write([]byte(content))
			require.NoError(t, err)
		}
		require.NoError(t, tw.Close())

		layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(tarBuf.Bytes())), nil
		})
		require.NoError(t, err)
		img, err := mutate.Append(empty.Image, mutate.Addendum{
			Layer:   layer,
			History: v1.History{CreatedBy: "COPY . /"},
		})
		require.NoError(t, err)

		var armed, failed atomic.Bool
		reg := registry.New(registry.Logger(stdlog.New(io.Discard, "", 0)))
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if armed.Load() && r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/manifests/") && !failed.Swap(true) {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			reg.ServeHTTP(w, r)
		}))
		t.Cleanup(srv.Close)

		ref := strings.TrimPrefix(srv.URL, "http://") + "/test/image:v1"
		tag, err := name.NewTag(ref)
		require.NoError(t, err)
		require.NoError(t, remote.Write(tag, img))
		armed.Store(true)
		return ref
	}

	runSource := func(t *testing.T, ctx context.Context) {
		conn, err := anypb.New(&sourcespb.Docker{
			Credential: &sourcespb.Docker_Unauthenticated{
				Unauthenticated: &credentialspb.Unauthenticated{},
			},
			Images:       []string{newFakeRegistry(t)},
			ExcludePaths: []string{"/skip/*"},
		})
		require.NoError(t, err)

		s := &Source{}
		require.NoError(t, s.Init(ctx, "test debug logging", 1, 1, false, conn, 1))

		chunksChan := make(chan *sources.Chunk, 8)
		require.NoError(t, s.Chunks(ctx, chunksChan))
		close(chunksChan)

		var files []string
		for chunk := range chunksChan {
			files = append(files, chunk.SourceMetadata.GetDocker().GetFile())
		}
		assert.ElementsMatch(t, []string{"image-metadata:history:0:created-by", "/secret.txt"}, files)
	}

	t.Run("debug on", func(t *testing.T) {
		ctx, logs := logtest.DebugContext()
		ctx = context.WithValues(ctx, "source_name", "test debug logging", "job_id", 1)
		runSource(t, ctx)

		// lines from each level show up
		for _, msg := range []string{
			"Docker source initialized",    // V(1)
			"Scanning image",               // V(2)
			"Finished scanning image",      // V(2)
			"Scanning image history entry", // V(3)
			"Scanning layer",               // V(3)
			"Finished scanning layer",      // V(3)
			"Skipping file",                // V(4)
			"Registry request failed",      // V(4)
			"Loading image",                // V(5)
			"Scanning file",                // V(5)
		} {
			assert.NotZero(t, logs.FilterMessage(msg).Len(), "missing log line %q", msg)
		}

		// the skip says why, and carries the layer
		skips := logs.FilterMessage("Skipping file").All()
		require.Len(t, skips, 1)
		assert.Equal(t, "/skip/me.txt", skips[0].ContextMap()["file"])
		assert.Equal(t, "matches exclude pattern", skips[0].ContextMap()["reason"])
		assert.Contains(t, skips[0].ContextMap(), "layer")

		layerDone := logs.FilterMessage("Finished scanning layer").All()
		require.Len(t, layerDone, 1)
		assert.EqualValues(t, 2, layerDone[0].ContextMap()["files"])
		assert.EqualValues(t, 1, layerDone[0].ContextMap()["skipped"])

		// the failed manifest request says what failed
		var manifestFailed bool
		for _, entry := range logs.FilterMessage("Registry request failed").All() {
			if entry.ContextMap()["status"] == int64(http.StatusServiceUnavailable) {
				manifestFailed = true
				assert.Equal(t, "/v2/test/image/manifests/v1", entry.ContextMap()["path"])
			}
		}
		assert.True(t, manifestFailed, "missing 503 registry line")

		// every line came from the context logger, so it carries the source fields,
		// and none of them contain the secret
		for _, entry := range logs.All() {
			fields := entry.ContextMap()
			assert.Contains(t, fields, "source_name", "line %q", entry.Message)
			assert.Contains(t, fields, "job_id", "line %q", entry.Message)
			assert.NotContains(t, entry.Message, testSecret)
			assert.NotContains(t, fmt.Sprint(fields), testSecret)
		}
	})

	t.Run("debug off", func(t *testing.T) {
		core, logs := observer.New(zapcore.InfoLevel)
		ctx := context.WithLogger(context.Background(), zapr.NewLogger(zap.New(core)))
		runSource(t, ctx)

		assert.Zero(t, logs.Len(), "unexpected lines: %v", logs.All())
	})
}

func TestDockerHub_ListImagesDebugLogging(t *testing.T) {
	ctx, logs := logtest.DebugContext()

	hub := &DockerHub{Client: &http.Client{Transport: common.FakeTransport{
		CreateResponse: func(req *http.Request) (*http.Response, error) {
			body := `{"next": "/v2/namespaces/acme/repositories?page=2", "results": [{"name": "one"}, {"name": "two"}]}`
			if req.URL.Query().Get("page") == "2" {
				body = `{"results": [{"name": "three"}]}`
			}
			return &http.Response{
				Request:    req,
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(body)),
			}, nil
		},
	}}}

	images, err := hub.ListImages(ctx, "acme")
	require.NoError(t, err)
	assert.Equal(t, []string{"acme/one", "acme/two", "acme/three"}, images)

	pages := logs.FilterMessage("Listed registry page").All()
	require.Len(t, pages, 2)
	for i, want := range []int{2, 1} {
		assert.EqualValues(t, i+1, pages[i].ContextMap()["page"])
		assert.EqualValues(t, want, pages[i].ContextMap()["images"])
		assert.Equal(t, "Dockerhub", pages[i].ContextMap()["registry"])
	}
}
