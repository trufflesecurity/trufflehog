package filesystem

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/kylelemons/godebug/pretty"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

func TestSource_Scan(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()

	type init struct {
		name       string
		verify     bool
		connection *sourcespb.Filesystem
	}
	tests := []struct {
		name               string
		init               init
		wantSourceMetadata *source_metadatapb.MetaData
		wantErr            bool
	}{
		{
			name: "get a chunk",
			init: init{
				name: "this repo",
				connection: &sourcespb.Filesystem{
					Paths: []string{"."},
				},
				verify: true,
			},
			wantSourceMetadata: &source_metadatapb.MetaData{
				Data: &source_metadatapb.MetaData_Filesystem{
					Filesystem: &source_metadatapb.Filesystem{
						File: "filesystem.go",
					},
				},
			},
			wantErr: false,
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
			if (err != nil) != tt.wantErr {
				t.Errorf("Source.Init() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			chunksCh := make(chan *sources.Chunk, 1)
			// TODO: this is kind of bad, if it errors right away we don't see it as a test failure.
			// Debugging this usually requires setting a breakpoint on L78 and running test w/ debug.
			go func() {
				err = s.Chunks(ctx, chunksCh)
				if (err != nil) != tt.wantErr {
					t.Errorf("Source.Chunks() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
			}()
			gotChunk := <-chunksCh
			if diff := pretty.Compare(gotChunk.SourceMetadata, tt.wantSourceMetadata); diff != "" {
				t.Errorf("Source.Chunks() %s diff: (-got +want)\n%s", tt.name, diff)
			}
		})
	}
}

func TestScanFile(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "example.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	chunkSize := sources.ChunkSize
	secretPart1 := "SECRET"
	secretPart2 := "SPLIT"
	// Split the secret into two parts and pad the rest of the chunk with A's.
	data := strings.Repeat("A", chunkSize-len(secretPart1)) + secretPart1 + secretPart2 + strings.Repeat("A", chunkSize-len(secretPart2))

	_, err = tmpfile.Write([]byte(data))
	assert.Nil(t, err)

	err = tmpfile.Close()
	assert.Nil(t, err)

	source := &Source{}
	chunksChan := make(chan *sources.Chunk, 2)

	ctx := context.WithLogger(context.Background(), logr.Discard())
	go func() {
		defer close(chunksChan)
		err = source.scanFile(ctx, tmpfile.Name(), chunksChan)
		assert.Nil(t, err)
	}()

	// Read from the channel and validate the secrets.
	foundSecret := ""
	for chunkCh := range chunksChan {
		foundSecret += string(chunkCh.Data)
	}

	assert.Contains(t, foundSecret, secretPart1+secretPart2)
}
