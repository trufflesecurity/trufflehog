package file

import (
	"testing"
	"time"

	"github.com/kylelemons/godebug/pretty"
	log "github.com/sirupsen/logrus"
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
		connection *sourcespb.File
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
				connection: &sourcespb.File{
					Path: "file.go",
				},
				verify: true,
			},
			wantSourceMetadata: &source_metadatapb.MetaData{
				Data: &source_metadatapb.MetaData_File{
					File: &source_metadatapb.File{
						Path: "file.go",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Source{}
			log.SetLevel(log.DebugLevel)
			log.SetFormatter(&log.TextFormatter{ForceColors: true})

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
