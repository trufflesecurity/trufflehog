//go:build localInfra
// +build localInfra

package jenkins

import (
	"fmt"
	"testing"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"

	"github.com/kylelemons/godebug/pretty"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/credentialspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

// Here’s how to test against Jenkins:

// Forward port from thog-dev_us-central1_dev-c1:
// kubectl --namespace jenkins port-forward svc/jenkins 8080:8080

// go test -timeout 10s -tags localInfra -run '^TestSource_Scan$' github.com/trufflesecurity/thog/scanner/pkg/sources/jenkins

func TestSource_Scan(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	secret, err := common.GetTestSecret(ctx)
	if err != nil {
		t.Fatal(fmt.Errorf("failed to access secret: %v", err))
	}
	jenkinsToken := secret.MustGetField("JENKINS_TOKEN")

	type init struct {
		name       string
		verify     bool
		connection *sourcespb.Jenkins
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
				connection: &sourcespb.Jenkins{
					Endpoint: "http://localhost:8080",
					Credential: &sourcespb.Jenkins_BasicAuth{
						BasicAuth: &credentialspb.BasicAuth{
							Username: "admin",
							Password: jenkinsToken,
						},
					},
				},
				verify: true,
			},
			wantSourceMetadata: &source_metadatapb.MetaData{
				Data: &source_metadatapb.MetaData_Jenkins{Jenkins: &source_metadatapb.Jenkins{
					ProjectName: "within-1-subfolder",
					BuildNumber: 1,
					Link:        "http://localhost:8080/job/folder1/job/sub-folder1/job/within-1-subfolder/1/consoleText",
				}},
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

func TestSource_ExpectBuilds(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	secret, err := common.GetTestSecret(ctx)
	if err != nil {
		t.Fatal(fmt.Errorf("failed to access secret: %v", err))
	}
	jenkinsToken := secret.MustGetField("JENKINS_TOKEN")

	type init struct {
		name       string
		verify     bool
		connection *sourcespb.Jenkins
	}
	tests := []struct {
		name                string
		init                init
		wantSourceMetadatas map[string]bool
		wantErr             bool
	}{
		{
			name: "get a chunk",
			init: init{
				name: "this repo",
				connection: &sourcespb.Jenkins{
					Endpoint: "http://localhost:8080",
					Credential: &sourcespb.Jenkins_BasicAuth{
						BasicAuth: &credentialspb.BasicAuth{
							Username: "admin",
							Password: jenkinsToken,
						},
					},
				},
				verify: true,
			},
			wantSourceMetadatas: map[string]bool{
				"http://localhost:8080/job/hon-test/1/consoleText":                  false,
				"http://localhost:8080/job/steeeve-freestyle-project/6/consoleText": false,
				"http://localhost:8080/job/steeeve-freestyle-project/5/consoleText": false,
				// Seems to 404? I assumed it would be there.
				// "http://localhost:8080/job/steeeve-freestyle-project/4/consoleText":           false,
				"http://localhost:8080/job/steeeve-freestyle-project/3/consoleText":                      false,
				"http://localhost:8080/job/steeeve-freestyle-project/2/consoleText":                      false,
				"http://localhost:8080/job/steeeve-freestyle-project/1/consoleText":                      false,
				"http://localhost:8080/job/folder1/job/within-1-folder/1/consoleText":                    false,
				"http://localhost:8080/job/folder1/job/sub-folder1/job/within-1-subfolder/1/consoleText": false,
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
			chunksCh := make(chan *sources.Chunk, 100)

			err = s.Chunks(ctx, chunksCh)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Source.Chunks() error = %v, wantErr %v", err, tt.wantErr)
			}
			close(chunksCh)

			for gotChunk := range chunksCh {
				if _, ok := tt.wantSourceMetadatas[gotChunk.SourceMetadata.GetJenkins().Link]; !ok {
					t.Errorf("encountered unexpected build: %s", gotChunk.SourceMetadata.GetJenkins().Link)
				}
				tt.wantSourceMetadatas[gotChunk.SourceMetadata.GetJenkins().Link] = true
			}

			for k, found := range tt.wantSourceMetadatas {
				if !found {
					t.Errorf("did not encounter expected build: %s", k)
				}
			}
		})
	}
}
