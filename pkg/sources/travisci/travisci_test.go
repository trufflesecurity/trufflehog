package travisci

import (
	"fmt"
	"testing"

	"github.com/kylelemons/godebug/pretty"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sourcestest"
)

func TestSource_Scan(t *testing.T) {
	ctx := context.Background()

	secret, err := common.GetTestSecret(ctx)
	if err != nil {
		t.Fatal(fmt.Errorf("failed to access secret: %v", err))
	}
	token := secret.MustGetField("TRAVISCI_TOKEN")

	type init struct {
		name       string
		verify     bool
		connection *sourcespb.TravisCI
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
				connection: &sourcespb.TravisCI{
					Credential: &sourcespb.TravisCI_Token{
						Token: token,
					},
				},
				verify: true,
			},
			wantSourceMetadata: &source_metadatapb.MetaData{
				Data: &source_metadatapb.MetaData_TravisCI{
					TravisCI: &source_metadatapb.TravisCI{
						Username:    "truffle-sandbox",
						Repository:  "test-repo",
						BuildNumber: "1",
						JobNumber:   "1.1",
						Link:        "https://app.travis-ci.com/github/truffle-sandbox/test-repo/jobs/611053994",
						Public:      false,
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
				t.Fatalf("Source.Init() error = %v, wantErr %v", err, tt.wantErr)
			}

			reporter := sourcestest.TestReporter{}
			s.returnAfterFirstChunk = true

			err = s.Enumerate(ctx, &reporter)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Source.Enumerate() error = %v, wantErr %v", err, tt.wantErr)
			}

			for _, unit := range reporter.Units {
				err = s.ChunkUnit(ctx, unit, &reporter)
				if (err != nil) != tt.wantErr {
					t.Fatalf("Source.ChunkUnit() error = %v, wantErr %v", err, tt.wantErr)
				}
			}

			for _, chunk := range reporter.Chunks {
				if diff := pretty.Compare(chunk.SourceMetadata, tt.wantSourceMetadata); diff != "" {
					t.Fatalf("comparing chunks: %s diff: (-got +want)\n%s", tt.name, diff)
				}
			}
		})
	}
}
