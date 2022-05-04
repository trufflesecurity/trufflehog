package github

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/google/go-github/v42/github"
	"github.com/kylelemons/godebug/pretty"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/anypb"
	"gopkg.in/h2non/gock.v1"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/credentialspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

func TestSource_Scan(t *testing.T) {
	//os.Setenv("DO_NOT_RANDOMIZE", "true")

	//ctx, cancel := context.WithTimeout(context.Background(), time.Second*300)
	//defer cancel()

	//secret, err := common.GetTestSecret(ctx)
	//if err != nil {
	//	t.Fatal(fmt.Errorf("failed to access secret: %v", err))
	//}

	//// For the personal access token test
	//githubToken := secret.MustGetField("GITHUB_TOKEN")

	////For the  NEW github app test (+Member enum)
	//githubPrivateKeyB64New := secret.MustGetField("GITHUB_PRIVATE_KEY_NEW")
	//githubPrivateKeyBytesNew, err := base64.StdEncoding.DecodeString(githubPrivateKeyB64New)
	//if err != nil {
	//	t.Fatal(err)
	//}
	//githubPrivateKeyNew := string(githubPrivateKeyBytesNew)
	//githubInstallationIDNew := secret.MustGetField("GITHUB_INSTALLATION_ID_NEW")
	//githubAppIDNew := secret.MustGetField("GITHUB_APP_ID_NEW")

	////OLD app for breaking app change tests
	//githubPrivateKeyB64 := secret.MustGetField("GITHUB_PRIVATE_KEY")
	//githubPrivateKeyBytes, err := base64.StdEncoding.DecodeString(githubPrivateKeyB64)
	//if err != nil {
	//	t.Fatal(err)
	//}
	//githubPrivateKey := string(githubPrivateKeyBytes)
	//githubInstallationID := secret.MustGetField("GITHUB_INSTALLATION_ID")
	//githubAppID := secret.MustGetField("GITHUB_APP_ID")

	//type init struct {
	//	name       string
	//	verify     bool
	//	connection *sourcespb.GitHub
	//}
	//tests := []struct {
	//	name      string
	//	init      init
	//	wantChunk *sources.Chunk
	//	wantErr   bool
	//	minRepo   int
	//	minOrg    int
	//}{
	//	{
	//		name: "token authenticated, single repo",
	//		init: init{
	//			name: "test source",
	//			connection: &sourcespb.GitHub{
	//				Repositories: []string{"https://github.com/dustin-decker/secretsandstuff.git"},
	//				Credential: &sourcespb.GitHub_Token{
	//					Token: githubToken,
	//				},
	//			},
	//		},
	//		wantChunk: &sources.Chunk{
	//			SourceType: sourcespb.SourceType_SOURCE_TYPE_GITHUB,
	//			SourceName: "test source",
	//			SourceMetadata: &source_metadatapb.MetaData{
	//				Data: &source_metadatapb.MetaData_Github{
	//					Github: &source_metadatapb.Github{
	//						Repository: "https://github.com/dustin-decker/secretsandstuff.git",
	//					},
	//				},
	//			},
	//			Verify: false,
	//		},
	//		wantErr: false,
	//	},
	//	{
	//		name: "token authenticated, single repo, no .git",
	//		init: init{
	//			name: "test source",
	//			connection: &sourcespb.GitHub{
	//				Repositories: []string{"https://github.com/dustin-decker/secretsandstuff"},
	//				Credential: &sourcespb.GitHub_Token{
	//					Token: githubToken,
	//				},
	//			},
	//		},
	//		wantChunk: &sources.Chunk{
	//			SourceType: sourcespb.SourceType_SOURCE_TYPE_GITHUB,
	//			SourceName: "test source",
	//			SourceMetadata: &source_metadatapb.MetaData{
	//				Data: &source_metadatapb.MetaData_Github{
	//					Github: &source_metadatapb.Github{
	//						Repository: "https://github.com/dustin-decker/secretsandstuff.git",
	//					},
	//				},
	//			},
	//			Verify: false,
	//		},
	//		wantErr: false,
	//	},
	//	{
	//		name: "token authenticated, single org",
	//		init: init{
	//			name: "test source",
	//			connection: &sourcespb.GitHub{
	//				Organizations: []string{"trufflesecurity"},
	//				Credential: &sourcespb.GitHub_Token{
	//					Token: githubToken,
	//				},
	//			},
	//		},
	//		wantChunk: nil,
	//		wantErr:   false,
	//		minRepo:   3,
	//		minOrg:    0,
	//	},
	//	{
	//		name: "token authenticated, username in org",
	//		init: init{
	//			name: "test source",
	//			connection: &sourcespb.GitHub{
	//				Organizations: []string{"dustin-decker"},
	//				Credential: &sourcespb.GitHub_Token{
	//					Token: githubToken,
	//				},
	//			},
	//		},
	//		wantChunk: nil,
	//		wantErr:   false,
	//		minRepo:   3,
	//		minOrg:    0,
	//	},
	//	{
	//		name: "token authenticated, username in repo",
	//		init: init{
	//			name: "test source",
	//			connection: &sourcespb.GitHub{
	//				Repositories: []string{"dustin-decker"},
	//				Credential: &sourcespb.GitHub_Token{
	//					Token: githubToken,
	//				},
	//			},
	//		},
	//		wantChunk: nil,
	//		wantErr:   false,
	//		minRepo:   3,
	//		minOrg:    0,
	//	},
	//	{
	//		name: "token authenticated, org in repo",
	//		// I do not think that this is a supported case, but adding the test to specify there is no requirement.
	//		init: init{
	//			name: "test source",
	//			connection: &sourcespb.GitHub{
	//				Repositories: []string{"trufflesecurity"},
	//				Credential: &sourcespb.GitHub_Token{
	//					Token: githubToken,
	//				},
	//			},
	//		},
	//		wantChunk: nil,
	//		wantErr:   false,
	//		minRepo:   0,
	//		minOrg:    0,
	//	},
	//	{
	//		name: "token authenticated, no org or user (enum)",
	//		// This configuration currently will only find gists from the user. No repos or orgs will be scanned.
	//		init: init{
	//			name: "test source",
	//			connection: &sourcespb.GitHub{
	//				Credential: &sourcespb.GitHub_Token{
	//					Token: githubToken,
	//				},
	//			},
	//		},
	//		wantChunk: nil,
	//		wantErr:   false,
	//		minRepo:   0,
	//		minOrg:    0,
	//	},
	//	{
	//		name: "app authenticated (old), no repo or org (enum)",
	//		init: init{
	//			name: "test source",
	//			connection: &sourcespb.GitHub{
	//				ScanUsers: false,
	//				Credential: &sourcespb.GitHub_GithubApp{
	//					GithubApp: &credentialspb.GitHubApp{
	//						PrivateKey:     githubPrivateKey,
	//						InstallationId: githubInstallationID,
	//						AppId:          githubAppID,
	//					},
	//				},
	//			},
	//		},
	//		wantChunk: nil,
	//		wantErr:   false,
	//		minRepo:   3,
	//		minOrg:    0,
	//	},
	//	{
	//		name: "unauthenticated, single org",
	//		init: init{
	//			name: "test source",
	//			connection: &sourcespb.GitHub{
	//				Organizations: []string{"trufflesecurity"},
	//				Credential:    &sourcespb.GitHub_Unauthenticated{},
	//			},
	//		},
	//		wantChunk: nil,
	//		wantErr:   false,
	//		minRepo:   3,
	//		minOrg:    1,
	//	},
	//	{
	//		name: "unauthenticated, single repo",
	//		init: init{
	//			name: "test source",
	//			connection: &sourcespb.GitHub{
	//				Repositories: []string{"https://github.com/trufflesecurity/driftwood.git"},
	//				Credential:   &sourcespb.GitHub_Unauthenticated{},
	//			},
	//		},
	//		wantChunk: &sources.Chunk{
	//			SourceType: sourcespb.SourceType_SOURCE_TYPE_GITHUB,
	//			SourceName: "test source",
	//			SourceMetadata: &source_metadatapb.MetaData{
	//				Data: &source_metadatapb.MetaData_Github{
	//					Github: &source_metadatapb.Github{
	//						Repository: "https://github.com/trufflesecurity/driftwood.git",
	//					},
	//				},
	//			},
	//			Verify: false,
	//		},
	//		wantErr: false,
	//	},
	//	{
	//		name: "app authenticated, no repo or org",
	//		init: init{
	//			name: "test source",
	//			connection: &sourcespb.GitHub{
	//				ScanUsers: true,
	//				Credential: &sourcespb.GitHub_GithubApp{
	//					GithubApp: &credentialspb.GitHubApp{
	//						PrivateKey:     githubPrivateKeyNew,
	//						InstallationId: githubInstallationIDNew,
	//						AppId:          githubAppIDNew,
	//					},
	//				},
	//			},
	//		},
	//		wantChunk: nil,
	//		wantErr:   false,
	//		minRepo:   3,
	//		minOrg:    0,
	//	},
	//	{
	//		name: "app authenticated, single repo",
	//		init: init{
	//			name: "test source",
	//			connection: &sourcespb.GitHub{
	//				Repositories: []string{"https://github.com/trufflesecurity/driftwood.git"},
	//				Credential: &sourcespb.GitHub_GithubApp{
	//					GithubApp: &credentialspb.GitHubApp{
	//						PrivateKey:     githubPrivateKeyNew,
	//						InstallationId: githubInstallationIDNew,
	//						AppId:          githubAppIDNew,
	//					},
	//				},
	//			},
	//		},
	//		wantChunk: &sources.Chunk{
	//			SourceType: sourcespb.SourceType_SOURCE_TYPE_GITHUB,
	//			SourceName: "test source",
	//			SourceMetadata: &source_metadatapb.MetaData{
	//				Data: &source_metadatapb.MetaData_Github{
	//					Github: &source_metadatapb.Github{
	//						Repository: "https://github.com/trufflesecurity/driftwood.git",
	//					},
	//				},
	//			},
	//			Verify: false,
	//		},
	//		wantErr: false,
	//		minRepo: 3,
	//		minOrg:  0,
	//	},
	//	{
	//		name: "app authenticated, single org",
	//		init: init{
	//			name: "test source",
	//			connection: &sourcespb.GitHub{
	//				Organizations: []string{"trufflesecurity"},
	//				Credential: &sourcespb.GitHub_GithubApp{
	//					GithubApp: &credentialspb.GitHubApp{
	//						PrivateKey:     githubPrivateKeyNew,
	//						InstallationId: githubInstallationIDNew,
	//						AppId:          githubAppIDNew,
	//					},
	//				},
	//			},
	//		},
	//		wantChunk: nil,
	//		wantErr:   false,
	//		minRepo:   3,
	//		minOrg:    1,
	//	},
	//}

	//for i, tt := range tests {
	//	t.Run(tt.name, func(t *testing.T) {
	//		log.Debugf("Beginning test %d: %s", i, tt.name)
	//		s := Source{}

	//		log.SetLevel(log.DebugLevel)
	//		//uncomment for windows Testing
	//		log.SetFormatter(&log.TextFormatter{ForceColors: true})
	//		log.SetOutput(colorable.NewColorableStdout())

	//		conn, err := anypb.New(tt.init.connection)
	//		if err != nil {
	//			t.Fatal(err)
	//		}

	//		err = s.Init(ctx, tt.init.name, 0, 0, tt.init.verify, conn, 4)
	//		if (err != nil) != tt.wantErr {
	//			t.Errorf("Source.Init() error = %v, wantErr %v", err, tt.wantErr)
	//			return
	//		}
	//		chunksCh := make(chan *sources.Chunk, 5)
	//		go func() {
	//			err = s.Chunks(ctx, chunksCh)
	//			if (err != nil) != tt.wantErr {
	//				if ctx.Err() != nil {
	//					return
	//				}
	//				t.Errorf("Source.Chunks() error = %v, wantErr %v", err, tt.wantErr)
	//				return
	//			}
	//		}()
	//		if err = common.HandleTestChannel(chunksCh, basicCheckFunc(tt.minOrg, tt.minRepo, tt.wantChunk, &s)); err != nil {
	//			t.Error(err)
	//		}
	//	})
	//}
}

func TestSource_paginateGists(t *testing.T) {

	//	os.Setenv("DO_NOT_RANDOMIZE", "true")

	//	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	//	defer cancel()

	//	secret, err := common.GetTestSecret(ctx)
	//	if err != nil {
	//		t.Fatal(fmt.Errorf("failed to access secret: %v", err))
	//	}
	//	//For the  NEW github app test (+Member enum)
	//	githubPrivateKeyB64New := secret.MustGetField("GITHUB_PRIVATE_KEY_NEW")
	//	githubPrivateKeyBytesNew, err := base64.StdEncoding.DecodeString(githubPrivateKeyB64New)
	//	if err != nil {
	//		t.Fatal(err)
	//	}
	//	githubPrivateKeyNew := string(githubPrivateKeyBytesNew)
	//	githubInstallationIDNew := secret.MustGetField("GITHUB_INSTALLATION_ID_NEW")
	//	githubAppIDNew := secret.MustGetField("GITHUB_APP_ID_NEW")
	//	type init struct {
	//		name       string
	//		verify     bool
	//		connection *sourcespb.GitHub
	//	}
	//	tests := []struct {
	//		name      string
	//		init      init
	//		wantChunk *sources.Chunk
	//		wantErr   bool
	//		user      string
	//		minRepos  int
	//	}{
	//		{
	//			name: "get gist secret",
	//			init: init{
	//				name: "test source",
	//				connection: &sourcespb.GitHub{
	//					Credential: &sourcespb.GitHub_GithubApp{
	//						GithubApp: &credentialspb.GitHubApp{
	//							PrivateKey:     githubPrivateKeyNew,
	//							InstallationId: githubInstallationIDNew,
	//							AppId:          githubAppIDNew,
	//						},
	//					},
	//				},
	//			},
	//			wantChunk: &sources.Chunk{
	//				SourceName: "test source",
	//				SourceMetadata: &source_metadatapb.MetaData{
	//					Data: &source_metadatapb.MetaData_Github{
	//						Github: &source_metadatapb.Github{
	//							Repository: "https://gist.github.com/be45ad1ebabe98482d9c0bb80c07c619.git",
	//						},
	//					},
	//				},
	//				Verify: false,
	//			},
	//			wantErr:  false,
	//			user:     "dustin-decker",
	//			minRepos: 1,
	//		},
	//		{
	//			name: "get multiple pages of gists",
	//			init: init{
	//				name: "test source",
	//				connection: &sourcespb.GitHub{
	//					Credential: &sourcespb.GitHub_GithubApp{
	//						GithubApp: &credentialspb.GitHubApp{
	//							PrivateKey:     githubPrivateKeyNew,
	//							InstallationId: githubInstallationIDNew,
	//							AppId:          githubAppIDNew,
	//						},
	//					},
	//				},
	//			},
	//			wantChunk: nil,
	//			wantErr:   false,
	//			user:      "andrew",
	//			minRepos:  101,
	//		},
	//		/*		{
	//					name: "get multiple pages of gists",
	//					init: init{
	//						name: "test source",
	//						connection: &sourcespb.GitHub{
	//							Credential: &sourcespb.GitHub_GithubApp{
	//								GithubApp: &credentialspb.GitHubApp{
	//									PrivateKey:     githubPrivateKeyNew,
	//									InstallationId: githubInstallationIDNew,
	//									AppId:          githubAppIDNew,
	//								},
	//							},
	//						},
	//					},
	//					wantChunk: &sources.Chunk{
	//						SourceName: "test source",
	//						SourceMetadata: &source_metadatapb.MetaData{
	//							Data: &source_metadatapb.MetaData_Github{
	//								Github: &source_metadatapb.Github{
	//									Repository: "https://gist.github.com/872df3b78b9ec3e7dbe597fb5a202121.git",
	//								},
	//							},
	//						},
	//						Verify: false,
	//					},
	//					wantErr: false,
	//					user:    "andrew",
	//				},
	//		*/
	//	}

	//	for _, tt := range tests {
	//		t.Run(tt.name, func(t *testing.T) {
	//			s := Source{}

	//			log.SetLevel(log.DebugLevel)
	//			//uncomment for windows Testing
	//			log.SetFormatter(&log.TextFormatter{ForceColors: true})
	//			log.SetOutput(colorable.NewColorableStdout())

	//			conn, err := anypb.New(tt.init.connection)
	//			if err != nil {
	//				t.Fatal(err)
	//			}

	//			err = s.Init(ctx, tt.init.name, 0, 0, tt.init.verify, conn, 4)
	//			if (err != nil) != tt.wantErr {
	//				t.Errorf("Source.Init() error = %v, wantErr %v", err, tt.wantErr)
	//				return
	//			}
	//			chunksCh := make(chan *sources.Chunk, 5)
	//			go func() {
	//				s.addGistsByUser(ctx, github.NewClient(s.httpClient), tt.user)
	//				chunksCh <- &sources.Chunk{}
	//			}()
	//			var wantedRepo string
	//			if tt.wantChunk != nil {
	//				wantedRepo = tt.wantChunk.SourceMetadata.GetGithub().Repository
	//			}
	//			if err = common.HandleTestChannel(chunksCh, gistsCheckFunc(wantedRepo, tt.minRepos, &s)); err != nil {
	//				t.Error(err)
	//			}
	//		})
	//	}
}

func createTestSource(src *sourcespb.GitHub) (*Source, *anypb.Any) {
	s := &Source{}
	conn, err := anypb.New(src)
	if err != nil {
		panic(err)
	}
	return s, conn
}

func initTestSource(src *sourcespb.GitHub) *Source {
	s, conn := createTestSource(src)
	if err := s.Init(context.TODO(), "test - github", 0, 1337, false, conn, 1); err != nil {
		panic(err)
	}
	return s
}

func TestInit(t *testing.T) {
	source, conn := createTestSource(&sourcespb.GitHub{
		Repositories: []string{"https://github.com/dustin-decker/secretsandstuff.git"},
		Credential: &sourcespb.GitHub_Token{
			Token: "super secret token",
		},
	})

	err := source.Init(context.TODO(), "test - github", 0, 1337, false, conn, 1)
	assert.Nil(t, err)

	// TODO: test error case
}

func TestAddReposByOrg(t *testing.T) {
	defer gock.Off()

	gock.New("https://api.github.com").
		Get("/orgs/super-secret-org/repos").
		Reply(200).
		JSON([]map[string]string{{"clone_url": "super-secret-repo"}})

	s := initTestSource(nil)
	// gock works here because github.NewClient is using the default HTTP Transport
	err := s.addReposByOrg(context.TODO(), github.NewClient(nil), "super-secret-org")
	assert.Nil(t, err)
	assert.Equal(t, 1, len(s.repos))
	assert.Equal(t, []string{"super-secret-repo"}, s.repos)
	assert.True(t, gock.IsDone())
}

func TestAddReposByUser(t *testing.T) {
	defer gock.Off()

	gock.New("https://api.github.com").
		Get("/users/super-secret-user/repos").
		Reply(200).
		JSON([]map[string]string{{"clone_url": "super-secret-repo"}})

	s := initTestSource(nil)
	err := s.addReposByUser(context.TODO(), github.NewClient(nil), "super-secret-user")
	assert.Nil(t, err)
	assert.Equal(t, 1, len(s.repos))
	assert.Equal(t, []string{"super-secret-repo"}, s.repos)
	assert.True(t, gock.IsDone())
}

func TestAddGistsByUser(t *testing.T) {
	defer gock.Off()

	gock.New("https://api.github.com").
		Get("/users/super-secret-user/gists").
		Reply(200).
		JSON([]map[string]string{{"git_pull_url": "super-secret-gist"}})

	s := initTestSource(nil)
	s.addGistsByUser(context.TODO(), github.NewClient(nil), "super-secret-user")
	assert.Equal(t, 1, len(s.repos))
	assert.Equal(t, []string{"super-secret-gist"}, s.repos)
	assert.True(t, gock.IsDone())
}

func TestAddMembersByApp(t *testing.T) {
	defer gock.Off()

	gock.New("https://api.github.com").
		Get("/app/installations").
		Reply(200).
		JSON([]map[string]interface{}{
			{"account": map[string]string{"login": "super-secret-org"}},
		})
	gock.New("https://api.github.com").
		Get("/orgs/super-secret-org/members").
		Reply(200).
		JSON([]map[string]interface{}{
			{"login": "ssm1"},
			{"login": "ssm2"},
			{"login": "ssm3"},
		})

	s := initTestSource(nil)
	err := s.addMembersByApp(context.TODO(), github.NewClient(nil), github.NewClient(nil))
	assert.Nil(t, err)
	assert.Equal(t, 3, len(s.members))
	assert.Equal(t, []string{"ssm1", "ssm2", "ssm3"}, s.members)
	assert.True(t, gock.IsDone())
}

func TestAddReposByApp(t *testing.T) {
	defer gock.Off()

	gock.New("https://api.github.com").
		Get("/installation/repositories").
		Reply(200).
		JSON(map[string]interface{}{
			"repositories": []map[string]string{
				{"clone_url": "ssr1"},
				{"clone_url": "ssr2"},
			},
		})

	s := initTestSource(nil)
	err := s.addReposByApp(context.TODO(), github.NewClient(nil))
	assert.Nil(t, err)
	assert.Equal(t, 2, len(s.repos))
	assert.Equal(t, []string{"ssr1", "ssr2"}, s.repos)
	assert.True(t, gock.IsDone())
}

func TestAddOrgsByUser(t *testing.T) {
	defer gock.Off()

	// NOTE: addOrgsByUser calls /user/orgs to get the orgs of the
	// authenticated user
	gock.New("https://api.github.com").
		Get("/user/orgs").
		Reply(200).
		JSON([]map[string]interface{}{
			{"name": "sso1"},
			{"login": "sso2"},
		})

	s := initTestSource(nil)
	s.addOrgsByUser(context.TODO(), github.NewClient(nil), "super-secret-user")
	assert.Equal(t, 2, len(s.orgs))
	assert.Equal(t, []string{"sso1", "sso2"}, s.orgs)
	assert.True(t, gock.IsDone())
}

// TODO: normalizeRepos doesn't appear correct
func TestNormalizeRepos(t *testing.T) {
	defer gock.Off()

	s := initTestSource(nil)
	s.repos = []string{"https://github.com/super-secret-user/super-secret-repo"}
	s.normalizeRepos(context.TODO(), github.NewClient(nil))

	assert.Equal(t, 2, len(s.repos))
	assert.Equal(t, []string{
		"https://github.com/super-secret-user/super-secret-repo",
		"https://github.com/super-secret-user/super-secret-repo.git",
	}, s.repos)

	gock.New("https://api.github.com").
		Get("/users/super-secret-user/gists").
		Reply(200).
		JSON([]map[string]string{{"git_pull_url": "super-secret-gist"}})
	gock.New("https://api.github.com").
		Get("/users/super-secret-user/repos").
		Reply(200).
		JSON([]map[string]string{{"clone_url": "super-secret-repo"}})
	s.repos = []string{"super-secret-user"}
	s.normalizeRepos(context.TODO(), github.NewClient(nil))

	assert.Equal(t, 2, len(s.repos))
	assert.Equal(t, []string{
		"super-secret-repo",
		"super-secret-gist",
	}, s.repos)

	gock.New("https://api.github.com").
		Get("/users/not-found/gists").
		Reply(404)
	gock.New("https://api.github.com").
		Get("/users/not-found/repos").
		Reply(404)

	s.repos = []string{"not-found"}
	s.normalizeRepos(context.TODO(), github.NewClient(nil))
	assert.Equal(t, 2, len(s.repos))
	assert.Equal(t, []string{
		"not-found",
		"",
	}, s.repos)

	assert.True(t, gock.IsDone())
}

func TestHandleRateLimit(t *testing.T) {
	assert.False(t, handleRateLimit(nil, nil))

	err := &github.RateLimitError{}
	res := &github.Response{Response: &http.Response{Header: make(http.Header, 0)}}
	res.Header.Set("x-ratelimit-remaining", "0")
	res.Header.Set("x-ratelimit-reset", strconv.FormatInt(time.Now().Unix()+1, 10))
	assert.True(t, handleRateLimit(err, res))
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

func TestEnumerateUnauthenticated(t *testing.T) {
	defer gock.Off()

	gock.New("https://api.github.com").
		Get("/orgs/super-secret-org/repos").
		Reply(200).
		JSON([]map[string]string{{"clone_url": "super-secret-repo"}})

	s := initTestSource(nil)
	s.orgs = []string{"super-secret-org"}
	_ = s.enumerateUnauthenticated(context.TODO())
	assert.Equal(t, 1, len(s.repos))
	assert.Equal(t, []string{"super-secret-repo"}, s.repos)
	assert.True(t, gock.IsDone())
}

func TestEnumerateWithToken(t *testing.T) {
	defer gock.Off()

	gock.New("https://api.github.com").
		Get("/user").
		Reply(200).
		JSON(map[string]string{"login": "super-secret-user"})

	gock.New("https://api.github.com").
		Get("/users/super-secret-user/repos").
		Reply(200).
		JSON([]map[string]string{{"clone_url": "super-secret-repo"}})

	s := initTestSource(nil)
	_, err := s.enumerateWithToken(context.TODO(), "https://api.github.com", "token")
	assert.Nil(t, err)
	assert.Equal(t, 1, len(s.repos))
	assert.Equal(t, []string{"super-secret-repo"}, s.repos)
	assert.True(t, gock.IsDone())
}

func TestEnumerateWithApp(t *testing.T) {
	defer gock.Off()

	// generate a private key (it just needs to be in the right format)
	privateKey := func() string {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}

		data := x509.MarshalPKCS1PrivateKey(key)
		var pemKey bytes.Buffer
		pem.Encode(&pemKey, &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: data,
		})
		return pemKey.String()
	}()

	gock.New("https://api.github.com").
		Post("/app/installations/1337/access_tokens").
		Reply(200).
		JSON(map[string]string{"token": "dontlook"})

	gock.New("https://api.github.com").
		Get("/installation/repositories").
		Reply(200).
		JSON(map[string]string{})

	s := initTestSource(nil)
	_, _, err := s.enumerateWithApp(
		context.TODO(),
		"https://api.github.com",
		&credentialspb.GitHubApp{
			InstallationId: "1337",
			AppId:          "4141",
			PrivateKey:     privateKey,
		},
	)
	fmt.Println(err)
	assert.Nil(t, err)
	assert.Equal(t, 0, len(s.repos))

	assert.True(t, gock.IsDone())
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
