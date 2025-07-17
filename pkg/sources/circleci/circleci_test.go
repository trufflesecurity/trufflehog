package circleci

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
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
			assert.NoError(t, err)

			err = s.Init(ctx, tt.init.name, 0, 0, tt.init.verify, conn, 5)
			assert.NoError(t, err)

			chunksCh := make(chan *sources.Chunk, 1000)
			chunksErr := s.Chunks(ctx, chunksCh)
			close(chunksCh)

			chunks := []*sources.Chunk{}
			for chunk := range chunksCh {
				chunks = append(chunks, chunk)
			}

			if tt.wantErr {
				assert.Error(t, chunksErr)
			}

			// verify minimum chunk count
			assert.GreaterOrEqual(t, len(chunks), tt.wantMinChunks)
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
