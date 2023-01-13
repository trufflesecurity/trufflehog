package npm

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

// func TestSource_Scan(t *testing.T) {
// 	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
// 	defer cancel()

// 	type init struct {
// 		name       string
// 		verify     bool
// 		connection *sourcespb.NPM
// 	}
// 	tests := []struct {
// 		name               string
// 		init               init
// 		wantSourceMetadata *source_metadatapb.MetaData
// 		wantErr            bool
// 	}{
// 		{
// 			name: "get a chunk",
// 			init: init{
// 				name: "example repo",
// 				connection: &sourcespb.NPM{
// 					Credential: &sourcespb.NPM_Unauthenticated{},
// 				},
// 				verify: true,
// 			},
// 			wantSourceMetadata: &source_metadatapb.MetaData{
// 				Data: &source_metadatapb.MetaData_Npm{
// 					Npm: &source_metadatapb.NPM{
// 						File:    "",
// 						Package: "",
// 						Release: "",
// 						Email:   "",
// 						Link:    "",
// 					},
// 				},
// 			},
// 			wantErr: false,
// 		},
// 	}
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			s := Source{}

// 			conn, err := anypb.New(tt.init.connection)
// 			if err != nil {
// 				t.Fatal(err)
// 			}

// 			err = s.Init(ctx, tt.init.name, 0, 0, tt.init.verify, conn, 5)
// 			if (err != nil) != tt.wantErr {
// 				t.Errorf("Source.Init() error = %v, wantErr %v", err, tt.wantErr)
// 				return
// 			}
// 			chunksCh := make(chan *sources.Chunk, 1)
// 			go func() {
// 				err = s.Chunks(ctx, chunksCh)
// 				if (err != nil) != tt.wantErr {
// 					t.Errorf("Source.Chunks() error = %v, wantErr %v", err, tt.wantErr)
// 					return
// 				}
// 			}()
// 			gotChunk := <-chunksCh
// 			if diff := pretty.Compare(gotChunk.SourceMetadata, tt.wantSourceMetadata); diff != "" {
// 				t.Errorf("Source.Chunks() %s diff: (-got +want)\n%s", tt.name, diff)
// 			}
// 		})
// 	}
// }

func TestSource_getPackage(t *testing.T) {
	type args struct {
		ctx         context.Context
		packageName string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "get a package",
			args: args{
				ctx:         context.Background(),
				packageName: "rawl-number-formatter",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Source{
				client: common.RetryableHttpClientTimeout(3),
			}
			got, err := s.getPackage(tt.args.ctx, tt.args.packageName)
			if (err != nil) != tt.wantErr {
				t.Errorf("Source.getPackage() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			assert.NotNil(t, got)
		})
	}
}

func TestSource_getPackagesByMaintainer(t *testing.T) {
	type args struct {
		ctx            context.Context
		maintainerName string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "get a package",
			args: args{
				ctx:            context.Background(),
				maintainerName: "sefasungur",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Source{
				client: common.RetryableHttpClientTimeout(3),
			}
			got, err := s.getPackagesByMaintainer(tt.args.ctx, tt.args.maintainerName)
			if (err != nil) != tt.wantErr {
				t.Errorf("Source.getPackage() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			assert.NotNil(t, got)
		})
	}
}
