//go:build integration
// +build integration

package github

import (
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/kylelemons/godebug/pretty"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/cache/simple"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/credentialspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
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

	src := &sourcespb.GitHub{
		Endpoint: "https://api.github.com",
		Credential: &sourcespb.GitHub_GithubApp{
			GithubApp: &credentialspb.GitHubApp{
				PrivateKey:     githubPrivateKeyNew,
				InstallationId: githubInstallationIDNew,
				AppId:          githubAppIDNew,
			},
		},
	}
	conn, err := anypb.New(src)
	if err != nil {
		panic(err)
	}

	s := Source{
		conn:          src,
		memberCache:   map[string]struct{}{},
		repoInfoCache: newRepoInfoCache(),
	}
	s.Init(ctx, "github integration test source", 0, 0, false, conn, 1)
	s.filteredRepoCache = s.newFilteredRepoCache(ctx, simple.NewCache[string](), nil, nil)

	err = s.enumerateWithApp(ctx, s.connector.(*appConnector).InstallationClient(), noopReporter())
	assert.NoError(t, err)

	_, _, err = s.cloneRepo(ctx, "https://github.com/truffle-test-integration-org/another-test-repo.git")
	assert.NoError(t, err)
}

func TestSource_paginateGists(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()

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
					Credential: &sourcespb.GitHub_Unauthenticated{},
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
		{
			name: "get multiple pages of gists",
			init: init{
				name: "test source",
				connection: &sourcespb.GitHub{
					Credential: &sourcespb.GitHub_Unauthenticated{},
				},
			},
			wantChunk: nil,
			wantErr:   false,
			user:      "andrew",
			minRepos:  101,
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
				assert.NoError(t, s.addUserGistsToCache(ctx, tt.user, noopReporter()))
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

func TestChunkUnit(t *testing.T) {
	ctx := context.Background()
	conn, _ := anypb.New(&sourcespb.GitHub{
		Repositories: []string{"https://github.com/trufflesecurity/driftwood.git"},
		Credential:   &sourcespb.GitHub_Unauthenticated{},
	})
	s := Source{}
	if err := s.Init(ctx, "github integration test source", 0, 0, false, conn, 1); err != nil {
		t.Errorf("Init() failed: %v", err)
	}

	unit := RepoUnit{Name: "driftwood", URL: "https://github.com/trufflesecurity/driftwood.git"}
	reporter := &countChunkReporter{}
	if err := s.ChunkUnit(ctx, unit, reporter); err != nil {
		t.Errorf("ChunkUnit() failed: %v", err)
	}
	assert.GreaterOrEqual(t, reporter.chunkCount, 65)
	assert.Equal(t, 0, reporter.errCount)
}

type countChunkReporter struct {
	chunkCount int
	errCount   int
}

func (m *countChunkReporter) ChunkOk(ctx context.Context, chunk sources.Chunk) error {
	m.chunkCount++
	return nil
}

func (m *countChunkReporter) ChunkErr(ctx context.Context, err error) error {
	m.errCount++
	return nil
}
