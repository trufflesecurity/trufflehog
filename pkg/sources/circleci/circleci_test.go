package circleci

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

func TestSource_Scan(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	secret, err := common.GetSecret(ctx, "trufflehog-testing", "test")
	if err != nil {
		t.Fatal(fmt.Errorf("failed to access secret: %v", err))
	}
	// Fix the chunks test, which might involve updating this token.
	token := secret.MustGetField("CIRCLECI_TOKEN")

	type init struct {
		name       string
		verify     bool
		connection *sourcespb.CircleCI
	}
	tests := []struct {
		name                 string
		init                 init
		wantErr              bool
		totalScannedProjects int32
	}{
		{
			name: "scan all projects",
			init: init{
				name: "trufflehog-test",
				connection: &sourcespb.CircleCI{
					Credential: &sourcespb.CircleCI_Token{
						Token: token,
					},
				},
				verify: true,
			},
			wantErr:              false,
			totalScannedProjects: 2,
		},
		{
			name: "invalid token",
			init: init{
				name: "invalid token test",
				connection: &sourcespb.CircleCI{
					Credential: &sourcespb.CircleCI_Token{
						Token: "invalid-token",
					},
				},
				verify: true,
			},
			wantErr:              true,
			totalScannedProjects: 0,
		},
		{
			name: "empty token",
			init: init{
				name: "empty token test",
				connection: &sourcespb.CircleCI{
					Credential: &sourcespb.CircleCI_Token{
						Token: "",
					},
				},
				verify: true,
			},
			wantErr:              true,
			totalScannedProjects: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Source{}

			conn, err := anypb.New(tt.init.connection)
			assert.NoError(t, err)

			err = s.Init(ctx, tt.init.name, 0, 0, tt.init.verify, conn, 5)
			assert.NoError(t, err)

			chunksCh := make(chan *sources.Chunk, 1000)
			chunkErr := s.Chunks(ctx, chunksCh)
			close(chunksCh)

			// check error
			if tt.wantErr {
				assert.Error(t, chunkErr)
			} else {
				assert.NoError(t, chunkErr)
			}

			// check total count of projects scanned
			progress := s.GetProgress()
			assert.Equal(t, tt.totalScannedProjects, progress.SectionsCompleted)
		})
	}
}

func TestGetOutputUrlResponseStreamsBody(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("partial log\n"))
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}

		close(started)
		<-release
		_, _ = w.Write([]byte("rest of log\n"))
	}))
	defer server.Close()
	defer close(release)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	s := &Source{client: server.Client()}
	done := make(chan struct {
		body io.ReadCloser
		err  error
	}, 1)

	go func() {
		body, err := s.getOutputUrlResponse(ctx, server.URL)
		done <- struct {
			body io.ReadCloser
			err  error
		}{body: body, err: err}
	}()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("test server did not start streaming the response")
	}

	select {
	case got := <-done:
		assert.NoError(t, got.err)
		if got.body != nil {
			_ = got.body.Close()
		}
	case <-time.After(time.Second):
		t.Fatal("getOutputUrlResponse waited for the whole response body")
	}
}

func TestChunkReadsFromReader(t *testing.T) {
	ctx := context.Background()
	s := Source{name: "test-circleci", verify: true}
	chunksCh := make(chan *sources.Chunk, 10)

	proj := project{
		VCS:      "github",
		Username: "trufflesecurity",
		Reponame: "trufflehog",
	}

	err := s.chunk(ctx, proj, 42, "run tests", strings.NewReader("hello\nCIRCLE_SHA1=abc123\nworld"), chunksCh)
	close(chunksCh)

	assert.NoError(t, err)
	require.Len(t, chunksCh, 1)

	chunk := <-chunksCh
	assert.Equal(t, "test-circleci", chunk.SourceName)
	assert.Equal(t, SourceType, chunk.SourceType)
	assert.True(t, chunk.SourceVerify)
	assert.NotContains(t, string(chunk.Data), "CIRCLE_SHA1")
	assert.Equal(t, "run tests", chunk.SourceMetadata.GetCircleci().BuildStep)
	assert.Equal(t, int64(42), chunk.SourceMetadata.GetCircleci().BuildNumber)
}

// additional test for edge cases
func TestSource_EdgeCases(t *testing.T) {
	tests := []struct {
		name string
		test func(t *testing.T)
	}{
		{
			name: "nil connection",
			test: func(t *testing.T) {
				s := Source{}
				err := s.Init(context.Background(), "test", 0, 0, false, nil, 5)
				assert.Error(t, err)
			},
		},
		{
			name: "cancelled context",
			test: func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				cancel() // cancel immediately

				s := Source{}
				conn, _ := anypb.New(&sourcespb.CircleCI{
					Credential: &sourcespb.CircleCI_Token{
						Token: "test-token",
					},
				})

				err := s.Init(ctx, "test", 0, 0, false, conn, 5)
				assert.NoError(t, err)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, tt.test)
	}
}
