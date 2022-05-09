//go:build integration
// +build integration

package github

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/go-github/v42/github"

	"github.com/kylelemons/godebug/pretty"
	"github.com/mattn/go-colorable"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/credentialspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
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
	// githubPrivateKeyB64 := secret.MustGetField("GITHUB_PRIVATE_KEY")
	// githubPrivateKeyBytes, err := base64.StdEncoding.DecodeString(githubPrivateKeyB64)
	// if err != nil {
	// 	t.Fatal(err)
	// }
	// githubPrivateKey := string(githubPrivateKeyBytes)
	// githubInstallationID := secret.MustGetField("GITHUB_INSTALLATION_ID")
	// githubAppID := secret.MustGetField("GITHUB_APP_ID")

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
		minRepo   int
		minOrg    int
	}{
		{
			name: "token authenticated, single repo",
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
							Repository: "https://github.com/dustin-decker/secretsandstuff.git",
						},
					},
				},
				Verify: false,
			},
			wantErr: false,
		},
		{
			name: "token authenticated, single repo, no .git",
			init: init{
				name: "test source",
				connection: &sourcespb.GitHub{
					Repositories: []string{"https://github.com/dustin-decker/secretsandstuff"},
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
							Repository: "https://github.com/dustin-decker/secretsandstuff.git",
						},
					},
				},
				Verify: false,
			},
			wantErr: false,
		},
		{
			name: "token authenticated, single org",
			init: init{
				name: "test source",
				connection: &sourcespb.GitHub{
					Organizations: []string{"trufflesecurity"},
					Credential: &sourcespb.GitHub_Token{
						Token: githubToken,
					},
				},
			},
			wantChunk: nil,
			wantErr:   false,
			minRepo:   3,
			minOrg:    0,
		},
		{
			name: "token authenticated, username in org",
			init: init{
				name: "test source",
				connection: &sourcespb.GitHub{
					Organizations: []string{"dustin-decker"},
					Credential: &sourcespb.GitHub_Token{
						Token: githubToken,
					},
				},
			},
			wantChunk: nil,
			wantErr:   false,
			minRepo:   3,
			minOrg:    0,
		},
		{
			name: "token authenticated, username in repo",
			init: init{
				name: "test source",
				connection: &sourcespb.GitHub{
					Repositories: []string{"dustin-decker"},
					Credential: &sourcespb.GitHub_Token{
						Token: githubToken,
					},
				},
			},
			wantChunk: nil,
			wantErr:   false,
			minRepo:   3,
			minOrg:    0,
		},
		{
			name: "token authenticated, org in repo",
			// I do not think that this is a supported case, but adding the test to specify there is no requirement.
			init: init{
				name: "test source",
				connection: &sourcespb.GitHub{
					Repositories: []string{"trufflesecurity"},
					Credential: &sourcespb.GitHub_Token{
						Token: githubToken,
					},
				},
			},
			wantChunk: nil,
			wantErr:   false,
			minRepo:   0,
			minOrg:    0,
		},
		/*
			{
				name: "token authenticated, no org or user (enum)",
				// This configuration currently will only find gists from the user. No repos or orgs will be scanned.
				init: init{
					name: "test source",
					connection: &sourcespb.GitHub{
						Credential: &sourcespb.GitHub_Token{
							Token: githubToken,
						},
					},
				},
				wantChunk: nil,
				wantErr:   false,
				minRepo:   0,
				minOrg:    0,
			},
			{
				name: "app authenticated (old), no repo or org (enum)",
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
				wantChunk: nil,
				wantErr:   false,
				minRepo:   3,
				minOrg:    0,
			},
		*/
		{
			name: "unauthenticated, single org",
			init: init{
				name: "test source",
				connection: &sourcespb.GitHub{
					Organizations: []string{"trufflesecurity"},
					Credential:    &sourcespb.GitHub_Unauthenticated{},
				},
			},
			wantChunk: nil,
			wantErr:   false,
			minRepo:   3,
			minOrg:    1,
		},
		{
			name: "unauthenticated, single repo",
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
		/*
			{
				name: "app authenticated, no repo or org",
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
				wantChunk: nil,
				wantErr:   false,
				minRepo:   3,
				minOrg:    0,
			},
		*/
		{
			name: "app authenticated, single repo",
			init: init{
				name: "test source",
				connection: &sourcespb.GitHub{
					Repositories: []string{"https://github.com/trufflesecurity/driftwood.git"},
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
							Repository: "https://github.com/trufflesecurity/driftwood.git",
						},
					},
				},
				Verify: false,
			},
			wantErr: false,
			minRepo: 1,
			minOrg:  0,
		},
		{
			name: "app authenticated, single org",
			init: init{
				name: "test source",
				connection: &sourcespb.GitHub{
					Organizations: []string{"trufflesecurity"},
					Credential: &sourcespb.GitHub_GithubApp{
						GithubApp: &credentialspb.GitHubApp{
							PrivateKey:     githubPrivateKeyNew,
							InstallationId: githubInstallationIDNew,
							AppId:          githubAppIDNew,
						},
					},
				},
			},
			wantChunk: nil,
			wantErr:   false,
			minRepo:   3,
			minOrg:    1,
		},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log.Debugf("Beginning test %d: %s", i, tt.name)
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
			if err = common.HandleTestChannel(chunksCh, basicCheckFunc(tt.minOrg, tt.minRepo, tt.wantChunk, &s)); err != nil {
				t.Error(err)
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
		user      string
		minRepos  int
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
			wantErr:  false,
			user:     "dustin-decker",
			minRepos: 1,
		},
		{
			name: "get multiple pages of gists",
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
			wantChunk: nil,
			wantErr:   false,
			user:      "andrew",
			minRepos:  101,
		},
		/*		{
					name: "get multiple pages of gists",
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
						SourceName: "test source",
						SourceMetadata: &source_metadatapb.MetaData{
							Data: &source_metadatapb.MetaData_Github{
								Github: &source_metadatapb.Github{
									Repository: "https://gist.github.com/872df3b78b9ec3e7dbe597fb5a202121.git",
								},
							},
						},
						Verify: false,
					},
					wantErr: false,
					user:    "andrew",
				},
		*/
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
				s.addGistsByUser(ctx, github.NewClient(s.httpClient), tt.user)
				chunksCh <- &sources.Chunk{}
			}()
			var wantedRepo string
			if tt.wantChunk != nil {
				wantedRepo = tt.wantChunk.SourceMetadata.GetGithub().Repository
			}
			if err = common.HandleTestChannel(chunksCh, gistsCheckFunc(wantedRepo, tt.minRepos, &s)); err != nil {
				t.Error(err)
			}
		})
	}
}

func gistsCheckFunc(expected string, minRepos int, s *Source) common.ChunkFunc {
	return func(chunk *sources.Chunk) error {
		if minRepos != 0 && minRepos > len(s.repos) {
			return fmt.Errorf("didn't find enough repos. expected: %d, got :%d", minRepos, len(s.repos))
		}
		if expected != "" {
			for _, repo := range s.repos {
				if repo == expected {
					return nil
				}
			}
			return fmt.Errorf("expected repo not included: %s", expected)
		}
		return nil
	}
}

func basicCheckFunc(minOrg, minRepo int, wantChunk *sources.Chunk, s *Source) common.ChunkFunc {
	return func(chunk *sources.Chunk) error {
		if minOrg != 0 && minOrg > len(s.orgs) {
			return fmt.Errorf("incorrect number of orgs. expected at least: %d, got %d", minOrg, len(s.orgs))
		}
		if minRepo != 0 && minRepo > len(s.repos) {
			return fmt.Errorf("incorrect number of repos. expected at least: %d, got %d", minRepo, len(s.repos))
		}
		if wantChunk != nil {
			if diff := pretty.Compare(chunk.SourceMetadata.GetGithub().Repository, wantChunk.SourceMetadata.GetGithub().Repository); diff == "" {
				return nil
			}
			return common.MatchError
		}
		return nil
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
