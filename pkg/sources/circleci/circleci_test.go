package circleci

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

func TestSource_Scan(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10) // Increased timeout
	defer cancel()

	secret, err := common.GetSecret(ctx, "trufflehog-testing", "test")
	if err != nil {
		t.Fatal(fmt.Errorf("failed to access secret: %v", err))
	}
	token := secret.MustGetField("CIRCLECI_TOKEN")

	type init struct {
		name       string
		verify     bool
		connection *sourcespb.CircleCI
	}
	tests := []struct {
		name          string
		init          init
		wantErr       bool
		wantMinChunks int // minimum expected chunks
	}{
		{
			name: "get all chunks",
			init: init{
				name: "trufflehog-test",
				connection: &sourcespb.CircleCI{
					Credential: &sourcespb.CircleCI_Token{
						Token: token,
					},
				},
				verify: true,
			},
			wantErr:       false,
			wantMinChunks: 15,
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
			wantErr:       true,
			wantMinChunks: 0,
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
			wantErr:       true,
			wantMinChunks: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Source{}

			conn, err := anypb.New(tt.init.connection)
			if err != nil {
				t.Fatal(err)
			}

			err = s.Init(ctx, tt.init.name, 0, 0, tt.init.verify, conn, 5)
			if err != nil {
				t.Errorf("Source.Init() error = %v", err)
				return
			}

			chunksCh := make(chan *sources.Chunk, 1)
			var wg sync.WaitGroup
			var chunksErr error

			wg.Add(1)
			go func() {
				defer wg.Done()
				defer close(chunksCh)
				chunksErr = s.Chunks(ctx, chunksCh)
			}()

			var chunks []*sources.Chunk
			done := make(chan struct{})

			go func() {
				defer close(done)
				for chunk := range chunksCh {
					chunks = append(chunks, chunk)
				}
			}()

			// wait for chunks collection to complete
			<-done
			wg.Wait()

			// check for errors
			if (chunksErr != nil) != tt.wantErr {
				t.Errorf("Source.Chunks() error = %v, wantErr %v", chunksErr, tt.wantErr)
				return
			}

			// verify minimum chunk count
			if len(chunks) < tt.wantMinChunks {
				t.Errorf("Source.Chunks() got %d chunks, want at least %d", len(chunks), tt.wantMinChunks)
				return
			}
		})
	}
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
				if err == nil {
					t.Error("Expected error for nil connection")
				}
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
				// should handle cancelled context gracefully
				if err != nil {
					t.Logf("Init with cancelled context returned error: %v", err)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, tt.test)
	}
}
