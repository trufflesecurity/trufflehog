package gitlab

import (
	"context"
	"fmt"
	"testing"

	"github.com/kylelemons/godebug/pretty"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"

	log "github.com/sirupsen/logrus"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

func TestSource_Scan(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log.SetLevel(log.DebugLevel)
	log.SetFormatter(&log.TextFormatter{ForceColors: true})
	secret, err := common.GetTestSecret(ctx)
	if err != nil {
		t.Fatal(fmt.Errorf("failed to access secret: %v", err))
	}
	token := secret.MustGetField("GITLAB_TOKEN")

	type init struct {
		name       string
		verify     bool
		connection *sourcespb.GitLab
	}
	tests := []struct {
		name      string
		init      init
		wantChunk *sources.Chunk
		wantErr   bool
	}{
		{
			name: "token auth, enumerate repo",
			init: init{
				name: "test source",
				connection: &sourcespb.GitLab{
					Credential: &sourcespb.GitLab_Token{
						Token: token,
					},
				},
			},
			wantChunk: &sources.Chunk{
				SourceType: sourcespb.SourceType_SOURCE_TYPE_GITLAB,
				SourceName: "test source",
				Verify:     false,
			},
			wantErr: false,
		},
		{
			name: "token auth, scoped repo",
			init: init{
				name: "test source scoped",
				connection: &sourcespb.GitLab{
					Repositories: []string{"https://gitlab.com/testermctestface/testy.git"},
					Credential: &sourcespb.GitLab_Token{
						Token: token,
					},
				},
			},
			wantChunk: &sources.Chunk{
				SourceType: sourcespb.SourceType_SOURCE_TYPE_GITLAB,
				SourceName: "test source scoped",
				Verify:     false,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Source{}
			log.SetLevel(log.DebugLevel)

			conn, err := anypb.New(tt.init.connection)
			if err != nil {
				t.Fatal(err)
			}

			err = s.Init(ctx, tt.init.name, 0, 0, tt.init.verify, conn, 10)
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
			// Commits don't come in a deterministic order, so remove metadata comparison
			gotChunk.Data = nil
			gotChunk.SourceMetadata = nil
			if diff := pretty.Compare(gotChunk, tt.wantChunk); diff != "" {
				t.Errorf("Source.Chunks() %s diff: (-got +want)\n%s", tt.name, diff)
			}
		})
	}
}
