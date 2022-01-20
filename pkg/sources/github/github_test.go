package github

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/kylelemons/godebug/pretty"
	"github.com/mattn/go-colorable"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/pkg/common"
	"github.com/trufflesecurity/trufflehog/pkg/pb/credentialspb"
	"github.com/trufflesecurity/trufflehog/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/pkg/sources"
)

func TestSource_Scan(t *testing.T) {

	os.Setenv("DO_NOT_RANDOMIZE", "true")

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*300)
	defer cancel()

	secret, err := common.GetTestSecret(ctx)
	if err != nil {
		t.Fatal(fmt.Errorf("failed to access secret: %v", err))
	}

	// For the personal access token test
	githubToken := secret.MustGetField("GITHUB_TOKEN")

	//For the  NEW github app test (+Member enum)
	githubPrivateKeyB64New := secret.MustGetField("GITHUB_PRIVATE_KEY_NEW")
	githubPrivateKeyBytesNew, err := base64.StdEncoding.DecodeString(githubPrivateKeyB64New)
	if err != nil {
		t.Fatal(err)
	}
	githubPrivateKeyNew := string(githubPrivateKeyBytesNew)
	githubInstallationIDNew := secret.MustGetField("GITHUB_INSTALLATION_ID_NEW")
	githubAppIDNew := secret.MustGetField("GITHUB_APP_ID_NEW")

	//OLD app for breaking app change tests
	githubPrivateKeyB64 := secret.MustGetField("GITHUB_PRIVATE_KEY")
	githubPrivateKeyBytes, err := base64.StdEncoding.DecodeString(githubPrivateKeyB64)
	if err != nil {
		t.Fatal(err)
	}
	githubPrivateKey := string(githubPrivateKeyBytes)
	githubInstallationID := secret.MustGetField("GITHUB_INSTALLATION_ID")
	githubAppID := secret.MustGetField("GITHUB_APP_ID")

	type init struct {
		name       string
		verify     bool
		connection *sourcespb.GitHub
	}
	tests := []struct {
		name      string
		init      init
		wantChunk *sources.Chunk
		wantErr   bool
	}{
		{
			name: "get an authenticated (token) chunk",
			init: init{
				name: "test source",
				connection: &sourcespb.GitHub{
					Repositories: []string{"https://github.com/dustin-decker/secretsandstuff.git"},
					Credential: &sourcespb.GitHub_Token{
						Token: githubToken,
					},
				},
			},
			wantChunk: &sources.Chunk{
				SourceType: sourcespb.SourceType_SOURCE_TYPE_GITHUB,
				SourceName: "test source",
				SourceMetadata: &source_metadatapb.MetaData{
					Data: &source_metadatapb.MetaData_Github{
						Github: &source_metadatapb.Github{
							Repository: "https://gist.github.com/be45ad1ebabe98482d9c0bb80c07c619.git",
						},
					},
				},
				Verify: false,
			},
			wantErr: false,
		},
		// {
		// 	name: "get an authenticated (token) chunk with specific 'org' enum",
		// 	init: init{
		// 		name: "test source",
		// 		connection: &sourcespb.GitHub{
		// 			Repositories: []string{"https://github.com/dustin-decker/"},
		// 			Credential: &sourcespb.GitHub_Token{
		// 				Token: githubToken,
		// 			},
		// 		},
		// 	},
		// 	wantChunk: &sources.Chunk{
		// 		SourceType: sourcespb.SourceType_SOURCE_TYPE_GITHUB,
		// 		SourceName: "test source",
		// 		SourceMetadata: &source_metadatapb.MetaData{
		// 			Data: &source_metadatapb.MetaData_Github{
		// 				Github: &source_metadatapb.Github{
		// 					Repository: "https://github.com/dustin-decker/secretsandstuff.git",
		// 				},
		// 			},
		// 		},
		// 		Verify: false,
		// 	},
		// 	wantErr: false,
		// },
		{
			name: "get an authenticated (token) chunk with enumeration",
			//Enum cannot be restricted w/ token
			init: init{
				name: "test source",
				connection: &sourcespb.GitHub{
					Credential: &sourcespb.GitHub_Token{
						Token: githubToken,
					},
				},
			},
			wantChunk: &sources.Chunk{
				SourceType: sourcespb.SourceType_SOURCE_TYPE_GITHUB,
				SourceName: "test source",
				SourceMetadata: &source_metadatapb.MetaData{
					Data: &source_metadatapb.MetaData_Github{
						Github: &source_metadatapb.Github{
							Repository: "https://gist.github.com/be45ad1ebabe98482d9c0bb80c07c619.git",
						},
					},
				},
				Verify: false,
			},
			wantErr: false,
		},
		{
			name: "get an authenticated (old app) chunk w/ enum",
			init: init{
				name: "test source",
				connection: &sourcespb.GitHub{
					ScanUsers: false,
					Credential: &sourcespb.GitHub_GithubApp{
						GithubApp: &credentialspb.GitHubApp{
							PrivateKey:     githubPrivateKey,
							InstallationId: githubInstallationID,
							AppId:          githubAppID,
						},
					},
				},
			},
			wantChunk: &sources.Chunk{
				SourceType: sourcespb.SourceType_SOURCE_TYPE_GITHUB,
				SourceName: "test source",
				SourceMetadata: &source_metadatapb.MetaData{
					Data: &source_metadatapb.MetaData_Github{
						Github: &source_metadatapb.Github{
							Repository: "https://github.com/dustin-decker/dockerfiles.git",
						},
					},
				},
				Verify: false,
			},
			wantErr: false,
		},
		{
			name: "get an unauthenticated org chunk with enumeration",
			init: init{
				name: "test source",
				connection: &sourcespb.GitHub{
					Organizations: []string{"trufflesecurity"},
					Credential:    &sourcespb.GitHub_Unauthenticated{},
				},
			},
			wantChunk: &sources.Chunk{
				SourceType: sourcespb.SourceType_SOURCE_TYPE_GITHUB,
				SourceName: "test source",
				SourceMetadata: &source_metadatapb.MetaData{
					Data: &source_metadatapb.MetaData_Github{
						Github: &source_metadatapb.Github{
							Repository: "https://github.com/trufflesecurity/driftwood.git",
						},
					},
				},
				Verify: false,
			},
			wantErr: false,
		},
		{
			name: "get an unauthenticated repo chunk with no enumeration",
			init: init{
				name: "test source",
				connection: &sourcespb.GitHub{
					Repositories: []string{"https://github.com/trufflesecurity/driftwood.git"},
					Credential:   &sourcespb.GitHub_Unauthenticated{},
				},
			},
			wantChunk: &sources.Chunk{
				SourceType: sourcespb.SourceType_SOURCE_TYPE_GITHUB,
				SourceName: "test source",
				SourceMetadata: &source_metadatapb.MetaData{
					Data: &source_metadatapb.MetaData_Github{
						Github: &source_metadatapb.Github{
							Repository: "https://github.com/trufflesecurity/driftwood.git",
						},
					},
				},
				Verify: false,
			},
			wantErr: false,
		},
		{
			name: "installed app on org w/ enum",
			init: init{
				name: "test source",
				connection: &sourcespb.GitHub{
					ScanUsers: true,
					Credential: &sourcespb.GitHub_GithubApp{
						GithubApp: &credentialspb.GitHubApp{
							PrivateKey:     githubPrivateKeyNew,
							InstallationId: githubInstallationIDNew,
							AppId:          githubAppIDNew,
						},
					},
				},
			},
			wantChunk: &sources.Chunk{
				SourceType: sourcespb.SourceType_SOURCE_TYPE_GITHUB,
				SourceName: "test source",
				SourceMetadata: &source_metadatapb.MetaData{
					Data: &source_metadatapb.MetaData_Github{
						Github: &source_metadatapb.Github{
							Repository: "https://gist.github.com/be45ad1ebabe98482d9c0bb80c07c619.git",
						},
					},
				},
				Verify: false,
			},
			wantErr: false,
		},
		// {
		// 	name: "early termination of org/users",
		// 	init: init{
		// 		name: "test source",
		// 		connection: &sourcespb.GitHub{
		// 			Repositories: strings.Split(testAccts, "\n"),
		// 			Credential:   &sourcespb.GitHub_Unauthenticated{},
		// 		},
		// 	},
		// 	wantChunk: &sources.Chunk{
		// 		SourceType: sourcespb.SourceType_SOURCE_TYPE_GITHUB,
		// 		SourceName: "test source",
		// 		SourceMetadata: &source_metadatapb.MetaData{
		// 			Data: &source_metadatapb.MetaData_Github{
		// 				Github: &source_metadatapb.Github{
		// 					Repository: "https://gist.github.com/be45ad1ebabe98482d9c0bb80c07c619.git",
		// 				},
		// 			},
		// 		},
		// 		Verify: false,
		// 	},
		// 	wantErr: false,
		// },
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Source{}

			log.SetLevel(log.DebugLevel)
			//uncomment for windows Testing
			log.SetFormatter(&log.TextFormatter{ForceColors: true})
			log.SetOutput(colorable.NewColorableStdout())

			conn, err := anypb.New(tt.init.connection)
			if err != nil {
				t.Fatal(err)
			}

			err = s.Init(ctx, tt.init.name, 0, 0, tt.init.verify, conn, 4)
			if (err != nil) != tt.wantErr {
				t.Errorf("Source.Init() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			chunksCh := make(chan *sources.Chunk, 5)
			go func() {
				err = s.Chunks(ctx, chunksCh)
				if (err != nil) != tt.wantErr {
					if ctx.Err() != nil {
						return
					}
					t.Errorf("Source.Chunks() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
			}()
			gotChunk := <-chunksCh
			if diff := pretty.Compare(gotChunk.SourceMetadata.GetGithub().Repository, tt.wantChunk.SourceMetadata.GetGithub().Repository); diff != "" {
				t.Errorf("Source.Chunks() %s diff: (-got +want)\n%s", tt.name, diff)
			}
		})
	}
}

func TestSource_paginateGists(t *testing.T) {

	os.Setenv("DO_NOT_RANDOMIZE", "true")

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()

	secret, err := common.GetTestSecret(ctx)
	if err != nil {
		t.Fatal(fmt.Errorf("failed to access secret: %v", err))
	}
	//For the  NEW github app test (+Member enum)
	githubPrivateKeyB64New := secret.MustGetField("GITHUB_PRIVATE_KEY_NEW")
	githubPrivateKeyBytesNew, err := base64.StdEncoding.DecodeString(githubPrivateKeyB64New)
	if err != nil {
		t.Fatal(err)
	}
	githubPrivateKeyNew := string(githubPrivateKeyBytesNew)
	githubInstallationIDNew := secret.MustGetField("GITHUB_INSTALLATION_ID_NEW")
	githubAppIDNew := secret.MustGetField("GITHUB_APP_ID_NEW")
	type init struct {
		name       string
		verify     bool
		connection *sourcespb.GitHub
	}
	tests := []struct {
		name      string
		init      init
		wantChunk *sources.Chunk
		wantErr   bool
	}{
		{
			name: "get gist secret",
			init: init{
				name: "test source",
				connection: &sourcespb.GitHub{
					Credential: &sourcespb.GitHub_GithubApp{
						GithubApp: &credentialspb.GitHubApp{
							PrivateKey:     githubPrivateKeyNew,
							InstallationId: githubInstallationIDNew,
							AppId:          githubAppIDNew,
						},
					},
				},
			},
			wantChunk: &sources.Chunk{
				SourceType: sourcespb.SourceType_SOURCE_TYPE_GITHUB,
				SourceName: "test source",
				SourceMetadata: &source_metadatapb.MetaData{
					Data: &source_metadatapb.MetaData_Github{
						Github: &source_metadatapb.Github{
							Repository: "https://gist.github.com/be45ad1ebabe98482d9c0bb80c07c619.git",
						},
					},
				},
				Verify: false,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Source{}

			log.SetLevel(log.DebugLevel)
			//uncomment for windows Testing
			log.SetFormatter(&log.TextFormatter{ForceColors: true})
			log.SetOutput(colorable.NewColorableStdout())

			conn, err := anypb.New(tt.init.connection)
			if err != nil {
				t.Fatal(err)
			}

			err = s.Init(ctx, tt.init.name, 0, 0, tt.init.verify, conn, 4)
			if (err != nil) != tt.wantErr {
				t.Errorf("Source.Init() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			chunksCh := make(chan *sources.Chunk, 5)
			go func() {
				s.paginateGists(ctx, "dustin-decker", chunksCh)
			}()
			gotChunk := <-chunksCh
			if diff := pretty.Compare(gotChunk.SourceMetadata.GetGithub().Repository, tt.wantChunk.SourceMetadata.GetGithub().Repository); diff != "" {
				t.Errorf("Source.Chunks() %s diff: (-got +want)\n%s", tt.name, diff)
			}
		})
	}
}

// func TestSource_paginateRepos(t *testing.T) {
// 	type args struct {
// 		ctx       context.Context
// 		apiClient *github.Client
// 	}
// 	tests := []struct {
// 		name string
// 		org  string
// 		args args
// 	}{
// 		{
// 			org: "fakeNetflix",
// 			args: args{
// 				ctx:       context.Background(),
// 				apiClient: github.NewClient(common.SaneHttpClient()),
// 			},
// 		},
// 	}
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			s := &Source{httpClient: common.SaneHttpClient()}
// 			s.paginateRepos(tt.args.ctx, tt.args.apiClient, tt.org)
// 			if len(s.repos) < 101 {
// 				t.Errorf("expected > 100 repos, got %d", len(s.repos))
// 			}
// 		})
// 	}
// }
