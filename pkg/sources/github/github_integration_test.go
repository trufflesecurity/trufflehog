//go:build integration
// +build integration

package github

import (
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/kylelemons/godebug/pretty"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/cache/memory"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/credentialspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/git"
)

func TestSource_Token(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*300)
	defer cancel()

	secret, err := common.GetTestSecret(ctx)
	if err != nil {
		t.Fatal(fmt.Errorf("failed to access secret: %v", err))
	}

	githubPrivateKeyB64New := secret.MustGetField("GITHUB_PRIVATE_KEY_NEW")
	githubPrivateKeyBytesNew, err := base64.StdEncoding.DecodeString(githubPrivateKeyB64New)
	if err != nil {
		t.Fatal(err)
	}
	githubPrivateKeyNew := string(githubPrivateKeyBytesNew)
	githubInstallationIDNew := secret.MustGetField("GITHUB_INSTALLATION_ID_NEW")
	githubAppIDNew := secret.MustGetField("GITHUB_APP_ID_NEW")

	conn := &sourcespb.GitHub{
		Credential: &sourcespb.GitHub_GithubApp{
			GithubApp: &credentialspb.GitHubApp{
				PrivateKey:     githubPrivateKeyNew,
				InstallationId: githubInstallationIDNew,
				AppId:          githubAppIDNew,
			},
		},
	}

	s := Source{
		conn:          conn,
		httpClient:    common.SaneHttpClient(),
		log:           logr.Discard(),
		memberCache:   map[string]struct{}{},
		repoInfoCache: newRepoInfoCache(),
	}
	s.filteredRepoCache = s.newFilteredRepoCache(memory.New(), nil, nil)

	installationClient, err := s.enumerateWithApp(ctx, "https://api.github.com", conn.GetGithubApp())
	assert.NoError(t, err)

	user, token, err := s.userAndToken(ctx, installationClient)
	assert.NotEmpty(t, token)
	assert.NoError(t, err)

	// user provided
	_, _, err = git.CloneRepoUsingToken(ctx, token, "https://github.com/truffle-test-integration-org/another-test-repo.git", user)
	assert.NoError(t, err)

	// no user provided
	_, _, err = git.CloneRepoUsingToken(ctx, token, "https://github.com/truffle-test-integration-org/another-test-repo.git", "")
	assert.Error(t, err)

	_, _, err = s.cloneRepo(ctx, "https://github.com/truffle-test-integration-org/another-test-repo.git", installationClient)
	assert.NoError(t, err)
}

func TestSource_ScanComments(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	secret, err := common.GetTestSecret(ctx)
	if err != nil {
		t.Fatal(fmt.Errorf("failed to access secret: %v", err))
	}

	// For the personal access token test
	githubToken := secret.MustGetField("GITHUB_TOKEN")

	const totalPRChunks = 2
	const totalIssueChunks = 1

	type init struct {
		name       string
		verify     bool
		connection *sourcespb.GitHub
	}
	tests := []struct {
		name              string
		init              init
		wantChunk         *sources.Chunk
		wantErr           bool
		minRepo           int
		minOrg            int
		numExpectedChunks int
	}{
		{
			name: "token authenticated, single repo, single issue comment",
			init: init{
				name: "test source",
				connection: &sourcespb.GitHub{
					Repositories:               []string{"https://github.com/truffle-test-integration-org/another-test-repo.git"},
					IncludeIssueComments:       true,
					IncludePullRequestComments: false,
					Credential: &sourcespb.GitHub_Token{
						Token: githubToken,
					},
				},
			},
			numExpectedChunks: totalIssueChunks,
			wantChunk: &sources.Chunk{
				SourceType: sourcespb.SourceType_SOURCE_TYPE_GITHUB,
				SourceName: "test source",
				SourceMetadata: &source_metadatapb.MetaData{
					Data: &source_metadatapb.MetaData_Github{
						Github: &source_metadatapb.Github{
							Link:      "https://github.com/truffle-test-integration-org/another-test-repo/issues/1#issuecomment-1603436833",
							Username:  "truffle-sandbox",
							Timestamp: "2023-06-22 23:33:46 +0000 UTC",
						},
					},
				},
				Verify: false,
			},
			wantErr: false,
		},
		{
			name: "token authenticated, single repo, pull request comment",
			init: init{
				name: "test source",
				connection: &sourcespb.GitHub{
					Repositories:               []string{"https://github.com/truffle-test-integration-org/another-test-repo.git"},
					IncludePullRequestComments: true,
					IncludeIssueComments:       false,
					Credential: &sourcespb.GitHub_Token{
						Token: githubToken,
					},
				},
			},
			numExpectedChunks: totalPRChunks,
			wantChunk: &sources.Chunk{
				SourceType: sourcespb.SourceType_SOURCE_TYPE_GITHUB,
				SourceName: "test source",
				SourceMetadata: &source_metadatapb.MetaData{
					Data: &source_metadatapb.MetaData_Github{
						Github: &source_metadatapb.Github{
							Link:      "https://github.com/truffle-test-integration-org/another-test-repo/pull/2#discussion_r1242763304",
							Username:  "truffle-sandbox",
							Timestamp: "2023-06-26 21:00:11 +0000 UTC",
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

			conn, err := anypb.New(tt.init.connection)
			if err != nil {
				t.Fatal(err)
			}

			err = s.Init(ctx, tt.init.name, 0, 0, tt.init.verify, conn, 4)
			if (err != nil) != tt.wantErr {
				t.Errorf("Source.Init() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			chunksCh := make(chan *sources.Chunk, 1)
			go func() {
				// Close the channel
				defer close(chunksCh)
				err = s.Chunks(ctx, chunksCh)
				if (err != nil) != tt.wantErr {
					if ctx.Err() != nil {
						return
					}
					t.Errorf("Source.Chunks() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
			}()

			i := 0
			for gotChunk := range chunksCh {
				// Skip chunks that are not comments.
				if gotChunk.SourceMetadata.GetGithub().GetCommit() != "" {
					continue
				}
				i++
				githubCommentCheckFunc(gotChunk, tt.wantChunk, i, t, tt.name)
			}

			// Confirm all comments were processed.
			if i != tt.numExpectedChunks {
				t.Errorf("did not complete all chunks, got %d, want %d", i, tt.numExpectedChunks)
			}

		})
	}
}

func TestSource_ScanChunks(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()

	secret, err := common.GetTestSecret(ctx)
	if err != nil {
		t.Fatal(fmt.Errorf("failed to access secret: %v", err))
	}

	// For the personal access token test.
	githubToken := secret.MustGetField("GITHUB_TOKEN")

	type init struct {
		name       string
		verify     bool
		connection *sourcespb.GitHub
	}
	tests := []struct {
		name       string
		init       init
		wantChunks int
	}{
		{
			name: "token authenticated, 4 repos",
			init: init{
				name: "test source",
				connection: &sourcespb.GitHub{
					Repositories: []string{
						"https://github.com/truffle-test-integration-org/another-test-repo.git",
						"https://github.com/trufflesecurity/trufflehog.git",
						"https://github.com/Akash-goyal-github/Inventory-Management-System.git",
						"https://github.com/R1ck404/Crypto-Exchange-Example.git",
						"https://github.com/Stability-AI/generative-models.git",
						"https://github.com/bloomberg/blazingmq.git",
						"https://github.com/Kong/kong.git",
					},
					Credential: &sourcespb.GitHub_Token{Token: githubToken},
				},
			},
			wantChunks: 20000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Source{}

			conn, err := anypb.New(tt.init.connection)
			if err != nil {
				t.Fatal(err)
			}

			err = s.Init(ctx, tt.init.name, 0, 0, tt.init.verify, conn, 8)
			assert.Nil(t, err)

			chunksCh := make(chan *sources.Chunk, 1)
			go func() {
				defer close(chunksCh)
				err = s.Chunks(ctx, chunksCh)
				assert.Nil(t, err)
			}()

			i := 0
			for range chunksCh {
				i++
			}
			assert.GreaterOrEqual(t, i, tt.wantChunks)
		})
	}
}

func TestSource_Scan(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*300)
	defer cancel()

	secret, err := common.GetTestSecret(ctx)
	if err != nil {
		t.Fatal(fmt.Errorf("failed to access secret: %v", err))
	}

	// For the personal access token test
	githubToken := secret.MustGetField("GITHUB_TOKEN")

	// For the  NEW github app test (+Member enum)
	githubPrivateKeyB64New := secret.MustGetField("GITHUB_PRIVATE_KEY_NEW")
	githubPrivateKeyBytesNew, err := base64.StdEncoding.DecodeString(githubPrivateKeyB64New)
	if err != nil {
		t.Fatal(err)
	}
	githubPrivateKeyNew := string(githubPrivateKeyBytesNew)
	githubInstallationIDNew := secret.MustGetField("GITHUB_INSTALLATION_ID_NEW")
	githubAppIDNew := secret.MustGetField("GITHUB_APP_ID_NEW")

	// OLD app for breaking app change tests
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
					Repositories: []string{"https://github.com/truffle-test-integration-org/another-test-repo.git"},
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
							Repository: "https://github.com/truffle-test-integration-org/another-test-repo.git",
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
					Repositories: []string{"https://github.com/truffle-test-integration-org/another-test-repo"},
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
							Repository: "https://github.com/truffle-test-integration-org/another-test-repo.git",
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
					Organizations: []string{"truffle-test-integration-org"},
					Credential: &sourcespb.GitHub_Token{
						Token: githubToken,
					},
				},
			},
			wantChunk: nil,
			wantErr:   false,
			minRepo:   1,
			minOrg:    0,
		},
		// {
		// 	name: "token authenticated, username in org",
		// 	init: init{
		// 		name: "test source",
		// 		connection: &sourcespb.GitHub{
		// 			Organizations: []string{"truffle-sandbox"},
		// 			Credential: &sourcespb.GitHub_Token{
		// 				Token: githubToken,
		// 			},
		// 		},
		// 	},
		// 	wantChunk: nil,
		// 	wantErr:   false,
		// 	minRepo:   0, // I think enumerating users with the org API does not work for newer users! Or maybe just newer users with a `-` in their name?
		// 	// See also: https://github.com/trufflesecurity/trufflehog/issues/874
		// 	minOrg: 0,
		// },
		// {
		// 	name: "token authenticated, org in repo",
		// 	// I do not think that this is a supported case, but adding the test to specify there is no requirement.
		// 	init: init{
		// 		name: "test source",
		// 		connection: &sourcespb.GitHub{
		// 			Repositories: []string{"truffle-test-integration-org"},
		// 			Credential: &sourcespb.GitHub_Token{
		// 				Token: githubToken,
		// 			},
		// 		},
		// 	},
		// 	wantChunk: nil,
		// 	wantErr:   false,
		// 	minRepo:   0,
		// 	minOrg:    0,
		// },
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
		// {
		// 	name: "unauthenticated, single org",
		// 	init: init{
		// 		name: "test source",
		// 		connection: &sourcespb.GitHub{
		// 			Organizations: []string{"trufflesecurity"},
		// 			Credential:    &sourcespb.GitHub_Unauthenticated{},
		// 		},
		// 	},
		// 	wantChunk: nil,
		// 	wantErr:   false,
		// 	minRepo:   3,
		// 	minOrg:    1,
		// },
		// {
		// 	name: "unauthenticated, single repo",
		// 	init: init{
		// 		name: "test source",
		// 		connection: &sourcespb.GitHub{
		// 			Repositories: []string{"https://github.com/trufflesecurity/driftwood.git"},
		// 			Credential:   &sourcespb.GitHub_Unauthenticated{},
		// 		},
		// 	},
		// 	wantChunk: &sources.Chunk{
		// 		SourceType: sourcespb.SourceType_SOURCE_TYPE_GITHUB,
		// 		SourceName: "test source",
		// 		SourceMetadata: &source_metadatapb.MetaData{
		// 			Data: &source_metadatapb.MetaData_Github{
		// 				Github: &source_metadatapb.Github{
		// 					Repository: "https://github.com/trufflesecurity/driftwood.git",
		// 				},
		// 			},
		// 		},
		// 		Verify: false,
		// 	},
		// 	wantErr: false,
		// },
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
			minRepo:   1,
			minOrg:    0,
		},
		{
			name: "app authenticated, single repo",
			init: init{
				name: "test source",
				connection: &sourcespb.GitHub{
					Repositories: []string{"https://github.com/truffle-test-integration-org/another-test-repo.git"},
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
							Repository: "https://github.com/truffle-test-integration-org/another-test-repo.git",
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
					Organizations: []string{"truffle-test-integration-org"},
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
			minRepo:   1,
			minOrg:    0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Source{}

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
			if err = sources.HandleTestChannel(chunksCh, basicCheckFunc(tt.minOrg, tt.minRepo, tt.wantChunk, &s)); err != nil {
				t.Error(err)
			}
		})
	}
}

func TestSource_paginateGists(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()

	secret, err := common.GetTestSecret(ctx)
	if err != nil {
		t.Fatal(fmt.Errorf("failed to access secret: %v", err))
	}
	// For the  NEW github app test (+Member enum)
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
			name: "get gist",
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
							Repository: "https://gist.github.com/fecf272c606ddbc5f8486f9c44821312.git",
						},
					},
				},
				Verify: false,
			},
			wantErr:  false,
			user:     "truffle-sandbox",
			minRepos: 1,
		},
		// {
		// 	name: "get multiple pages of gists",
		// 	init: init{
		// 		name: "test source",
		// 		connection: &sourcespb.GitHub{
		// 			Credential: &sourcespb.GitHub_GithubApp{
		// 				GithubApp: &credentialspb.GitHubApp{
		// 					PrivateKey:     githubPrivateKeyNew,
		// 					InstallationId: githubInstallationIDNew,
		// 					AppId:          githubAppIDNew,
		// 				},
		// 			},
		// 		},
		// 	},
		// 	wantChunk: nil,
		// 	wantErr:   false,
		// 	user:      "andrew",
		// 	minRepos:  101,
		// },
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
				s.addUserGistsToCache(ctx, tt.user)
				chunksCh <- &sources.Chunk{}
			}()
			var wantedRepo string
			if tt.wantChunk != nil {
				wantedRepo = tt.wantChunk.SourceMetadata.GetGithub().Repository
			}
			if err = sources.HandleTestChannel(chunksCh, gistsCheckFunc(wantedRepo, tt.minRepos, &s)); err != nil {
				t.Error(err)
			}
		})
	}
}

func gistsCheckFunc(expected string, minRepos int, s *Source) sources.ChunkFunc {
	return func(chunk *sources.Chunk) error {
		if minRepos != 0 && minRepos > s.filteredRepoCache.Count() {
			return fmt.Errorf("didn't find enough repos. expected: %d, got :%d", minRepos, len(s.repos))
		}
		if expected != "" {
			for _, repo := range s.filteredRepoCache.Values() {
				if repo == expected {
					return nil
				}
			}
			return fmt.Errorf("expected repo not included: %s", expected)
		}
		return nil
	}
}

func basicCheckFunc(minOrg, minRepo int, wantChunk *sources.Chunk, s *Source) sources.ChunkFunc {
	return func(chunk *sources.Chunk) error {
		if minOrg != 0 && minOrg > s.orgsCache.Count() {
			return fmt.Errorf("incorrect number of orgs. expected at least: %d, got %d", minOrg, s.orgsCache.Count())
		}
		if minRepo != 0 && minRepo > len(s.repos) {
			return fmt.Errorf("incorrect number of repos. expected at least: %d, got %d", minRepo, len(s.repos))
		}
		if wantChunk != nil {
			if diff := pretty.Compare(chunk.SourceMetadata.GetGithub().Repository, wantChunk.SourceMetadata.GetGithub().Repository); diff == "" {
				return nil
			}
			return sources.MatchError
		}
		return nil
	}
}

func githubCommentCheckFunc(gotChunk, wantChunk *sources.Chunk, i int, t *testing.T, name string) {
	if gotChunk.SourceType != wantChunk.SourceType {
		t.Errorf("want SourceType %v, got %v", wantChunk.SourceType, gotChunk.SourceType)
	}

	assert.NotEmpty(t, gotChunk.SourceMetadata.Data, "SourceMetadata.Data should not be empty")

	// First Chunk should be a Issue Comment, Second Chunk should be a PR Comment.
	if i == 1 && name == "token authenticated, single repo, single issue comment" &&
		wantChunk.SourceMetadata.GetGithub().GetLink() != gotChunk.SourceMetadata.GetGithub().GetLink() {
		t.Errorf("want %+v \n got %+v \n", wantChunk.SourceMetadata.GetGithub().GetLink(), gotChunk.SourceMetadata.GetGithub().GetLink())
	} else if i == 2 && name == "token authenticated, single repo, single pr comment" &&
		wantChunk.SourceMetadata.GetGithub().GetLink() != gotChunk.SourceMetadata.GetGithub().GetLink() {
		t.Errorf("want %+v \n got %+v \n", wantChunk.SourceMetadata.GetGithub().GetLink(), gotChunk.SourceMetadata.GetGithub().GetLink())
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

func TestSource_Chunks_TargetedScan(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3000)
	defer cancel()

	secret, err := common.GetTestSecret(ctx)
	if err != nil {
		t.Fatal(fmt.Errorf("failed to access secret: %v", err))
	}

	githubToken := secret.MustGetField("GITHUB_TOKEN")

	type init struct {
		name          string
		verify        bool
		connection    *sourcespb.GitHub
		queryCriteria *source_metadatapb.MetaData
	}
	tests := []struct {
		name       string
		init       init
		wantChunks int
	}{
		{
			name: "targeted scan, one file in small commit",
			init: init{
				name:       "test source",
				connection: &sourcespb.GitHub{Credential: &sourcespb.GitHub_Token{Token: githubToken}},
				queryCriteria: &source_metadatapb.MetaData{
					Data: &source_metadatapb.MetaData_Github{
						Github: &source_metadatapb.Github{
							Repository: "test_keys",
							Link:       "https://github.com/trufflesecurity/test_keys/blob/fbc14303ffbf8fb1c2c1914e8dda7d0121633aca/keys#L4",
							Commit:     "fbc14303ffbf8fb1c2c1914e8dda7d0121633aca",
							File:       "keys",
						},
					},
				},
			},
			wantChunks: 1,
		},
		{
			name: "targeted scan, one file in med commit",
			init: init{
				name:       "test source",
				connection: &sourcespb.GitHub{Credential: &sourcespb.GitHub_Token{Token: githubToken}},
				queryCriteria: &source_metadatapb.MetaData{
					Data: &source_metadatapb.MetaData_Github{
						Github: &source_metadatapb.Github{
							Repository: "https://github.com/trufflesecurity/trufflehog.git",
							Link:       "https://github.com/trufflesecurity/trufflehog/blob/33eed42e17fda8b1a66feaeafcd57efccff26c11/pkg/sources/s3/s3_test.go#L78",
							Commit:     "33eed42e17fda8b1a66feaeafcd57efccff26c11",
							File:       "pkg/sources/s3/s3_test.go",
						},
					},
				},
			},
			wantChunks: 1,
		},
		{
			name: "no file in commit",
			init: init{
				name:       "test source",
				connection: &sourcespb.GitHub{Credential: &sourcespb.GitHub_Token{Token: githubToken}},
				queryCriteria: &source_metadatapb.MetaData{
					Data: &source_metadatapb.MetaData_Github{
						Github: &source_metadatapb.Github{
							Repository: "test_keys",
							Link:       "https://github.com/trufflesecurity/test_keys/blob/fbc14303ffbf8fb1c2c1914e8dda7d0121633aca/keys#L4",
							Commit:     "fbc14303ffbf8fb1c2c1914e8dda7d0121633aca",
							File:       "not-the-file",
						},
					},
				},
			},
			wantChunks: 0,
		},
		{
			name: "invalid query criteria, malformed link",
			init: init{
				name:       "test source",
				connection: &sourcespb.GitHub{Credential: &sourcespb.GitHub_Token{Token: githubToken}},
				queryCriteria: &source_metadatapb.MetaData{
					Data: &source_metadatapb.MetaData_Github{
						Github: &source_metadatapb.Github{
							Repository: "test_keys",
							Link:       "malformed-link",
							Commit:     "fbc14303ffbf8fb1c2c1914e8dda7d0121633aca",
							File:       "not-the-file",
						},
					},
				},
			},
			wantChunks: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Source{}

			conn, err := anypb.New(tt.init.connection)
			assert.Nil(t, err)

			err = s.Init(ctx, tt.init.name, 0, 0, tt.init.verify, conn, 8)
			assert.Nil(t, err)

			chunksCh := make(chan *sources.Chunk, 1)
			go func() {
				defer close(chunksCh)
				err = s.Chunks(ctx, chunksCh, sources.ChunkingTarget{QueryCriteria: tt.init.queryCriteria})
				assert.Nil(t, err)
			}()

			i := 0
			for range chunksCh {
				i++
			}
			assert.Equal(t, tt.wantChunks, i)
		})
	}
}
