package circleci

import (
	"fmt"
	"testing"
	"time"

	"github.com/kylelemons/godebug/pretty"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

func TestSource_Scan(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()

	secret, err := common.GetTestSecret(ctx)
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
		name               string
		init               init
		wantSourceMetadata *source_metadatapb.MetaData
		wantErr            bool
	}{
		{
			name: "get a chunk",
			init: init{
				name: "example repo",
				connection: &sourcespb.CircleCI{
					Credential: &sourcespb.CircleCI_Token{
						Token: token,
					},
				},
				verify: true,
			},
			wantSourceMetadata: &source_metadatapb.MetaData{
				Data: &source_metadatapb.MetaData_Circleci{
					Circleci: &source_metadatapb.CircleCI{
						VcsType:     "github",
						Username:    "dustin-decker",
						Repository:  "circle-ci",
						BuildNumber: 2,
						BuildStep:   "Spin up environment",
						Link:        "https://app.circleci.com/pipelines/github/dustin-decker/circle-ci/2",
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
