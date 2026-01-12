//go:build integration
// +build integration

package gitlab

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/kylelemons/godebug/pretty"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/credentialspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sourcestest"
)

func TestSource_Scan(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	secret, err := common.GetTestSecret(ctx)
	if err != nil {
		t.Fatal(fmt.Errorf("failed to access secret: %v", err))
	}
	token := secret.MustGetField("GITLAB_TOKEN")
	basicUser := secret.MustGetField("GITLAB_USER")
	no2FaUser := secret.MustGetField("GITLAB_NO_2FA_USER")
	no2FaPass := secret.MustGetField("GITLAB_NO_2FA_PASS")

	type init struct {
		name       string
		verify     bool
		connection *sourcespb.GitLab
	}
	tests := []struct {
		name             string
		init             init
		wantChunk        *sources.Chunk
		wantReposScanned int
		wantErr          bool
	}{
		{
			name: "token auth, enumerate repo, with explicit ignore",
			init: init{
				name: "test source",
				connection: &sourcespb.GitLab{
					Credential: &sourcespb.GitLab_Token{
						Token: token,
					},
					IgnoreRepos: []string{"tes1188/learn-gitlab"},
				},
			},
			wantChunk: &sources.Chunk{
				SourceType: sourcespb.SourceType_SOURCE_TYPE_GITLAB,
				SourceName: "test source",
			},
			wantReposScanned: 5,
		},
		{
			name: "token auth, enumerate repo, with glob ignore",
			init: init{
				name: "test source",
				connection: &sourcespb.GitLab{
					Credential: &sourcespb.GitLab_Token{
						Token: token,
					},
					IgnoreRepos: []string{"tes1188/*-gitlab"},
				},
			},
			wantChunk: &sources.Chunk{
				SourceType: sourcespb.SourceType_SOURCE_TYPE_GITLAB,
				SourceName: "test source",
			},
			wantReposScanned: 5,
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
			},
			wantReposScanned: 1,
		},
		{
			name: "basic auth, scoped repo",
			init: init{
				name: "test source basic auth scoped",
				connection: &sourcespb.GitLab{
					Repositories: []string{"https://gitlab.com/trufflesec-detectors/test-project.git"},

					Credential: &sourcespb.GitLab_BasicAuth{
						BasicAuth: &credentialspb.BasicAuth{
							Username: no2FaUser,
							Password: no2FaPass,
						},
					},
				},
			},
			wantChunk: &sources.Chunk{
				SourceType: sourcespb.SourceType_SOURCE_TYPE_GITLAB,
				SourceName: "test source basic auth scoped",
			},
			wantReposScanned: 1,
		},
		{
			name: "basic auth access token, scoped repo",
			init: init{
				name: "test source basic auth access token scoped",
				connection: &sourcespb.GitLab{
					Repositories: []string{"https://gitlab.com/testermctestface/testy.git"},
					Credential: &sourcespb.GitLab_BasicAuth{
						BasicAuth: &credentialspb.BasicAuth{
							Username: basicUser,
							Password: token,
						},
					},
				},
			},
			wantChunk: &sources.Chunk{
				SourceType: sourcespb.SourceType_SOURCE_TYPE_GITLAB,
				SourceName: "test source basic auth access token scoped",
			},
			wantReposScanned: 1,
		},
		{
			name: "token auth, group projects enumeration with include_subgroups",
			init: init{
				name: "test source group enumeration",
				connection: &sourcespb.GitLab{
					Credential: &sourcespb.GitLab_Token{
						Token: token,
					},
					GroupIds: []string{"15013490"},
				},
			},
			wantChunk: &sources.Chunk{
				SourceType: sourcespb.SourceType_SOURCE_TYPE_GITLAB,
				SourceName: "test source group enumeration",
			},
			wantReposScanned: 5,
		},
		{
			name: "token auth, group projects enumeration with include_subgroups and exclude repositories",
			init: init{
				name: "test source group enumeration with exclude repos",
				connection: &sourcespb.GitLab{
					Credential: &sourcespb.GitLab_Token{
						Token: token,
					},
					GroupIds:    []string{"15013490"},
					IgnoreRepos: []string{"tes1188/test-user-count"},
				},
			},
			wantChunk: &sources.Chunk{
				SourceType: sourcespb.SourceType_SOURCE_TYPE_GITLAB,
				SourceName: "test source group enumeration with exclude repos",
			},
			wantReposScanned: 4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Source{}

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
				defer close(chunksCh)
				err = s.Chunks(ctx, chunksCh)
				if (err != nil) != tt.wantErr {
					t.Errorf("Source.Chunks() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
			}()
			var chunkCnt int
			// Commits don't come in a deterministic order, so remove metadata comparison
			for gotChunk := range chunksCh {
				chunkCnt++
				gotChunk.Data = nil
				gotChunk.SourceMetadata = nil
				if diff := pretty.Compare(gotChunk, tt.wantChunk); diff != "" {
					t.Errorf("Source.Chunks() %s diff: (-got +want)\n%s", tt.name, diff)
				}
			}

			assert.Equal(t, tt.wantReposScanned, len(s.repos))
			if chunkCnt < 1 {
				t.Errorf("0 chunks scanned.")
			}
		})
	}
}

func TestSource_Validate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	secret, err := common.GetTestSecret(ctx)
	if err != nil {
		t.Fatal(fmt.Errorf("failed to access secret: %v", err))
	}
	token := secret.MustGetField("GITLAB_TOKEN")
	tokenWrongScope := secret.MustGetField("GITLAB_TOKEN_WRONG_SCOPE")

	tests := []struct {
		name         string
		connection   *sourcespb.GitLab
		wantErrCount int
		wantErrs     []string
	}{
		{
			name: "basic auth did not authenticate",
			connection: &sourcespb.GitLab{
				Credential: &sourcespb.GitLab_BasicAuth{
					BasicAuth: &credentialspb.BasicAuth{
						Username: "bad-user",
						Password: "bad-password",
					},
				},
			},
			wantErrCount: 1,
		},
		{
			name: "token did not authenticate",
			connection: &sourcespb.GitLab{
				Credential: &sourcespb.GitLab_Token{
					Token: "bad-token",
				},
			},
			wantErrCount: 1,
		},
		{
			name: "bad repo urls",
			connection: &sourcespb.GitLab{
				Credential: &sourcespb.GitLab_Token{
					Token: token,
				},
				Repositories: []string{
					"https://gitlab.com/testermctestface/testy",  // valid
					"https://gitlab.com/testermctestface/testy/", // trailing slash
					"ssh:git@gitlab.com/testermctestface/testy",  // bad protocol
					"https://gitlab.com",                         // no path
					"https://gitlab.com/",                        // no org name
					"https://gitlab.com//testy",                  // no org name
					"https://gitlab.com/testermctestface/",       // no repo name
				},
			},
			wantErrCount: 6,
		},
		{
			name: "token does not have permission to list projects",
			connection: &sourcespb.GitLab{
				Credential: &sourcespb.GitLab_Token{
					Token: tokenWrongScope,
				},
			},
			wantErrCount: 1,
		},
		{
			name: "repositories and ignore globs both configured",
			connection: &sourcespb.GitLab{
				Credential: &sourcespb.GitLab_Token{
					Token: token,
				},
				Repositories: []string{
					"https://gitlab.com/testermctestface/testy", // valid
				},
				IgnoreRepos: []string{
					"tes1188/*-gitlab",
					"[", // glob doesn't compile, but this won't be checked
				},
			},
			wantErrCount: 1,
		},
		{
			name: "could not compile ignore glob(s)",
			connection: &sourcespb.GitLab{
				Credential: &sourcespb.GitLab_Token{
					Token: token,
				},
				IgnoreRepos: []string{
					"tes1188/*-gitlab",
					"[",    // glob doesn't compile
					"[a-]", // glob doesn't compile
				},
			},
			wantErrCount: 2,
		},

		{
			name: "could not compile include glob(s)",
			connection: &sourcespb.GitLab{
				Credential: &sourcespb.GitLab_Token{
					Token: token,
				},
				IncludeRepos: []string{
					"tes1188/*-gitlab",
					"[",    // glob doesn't compile
					"[a-]", // glob doesn't compile
				},
				IgnoreRepos: []string{
					"[",
				},
			},
			wantErrCount: 3,
		},
		{
			name: "repositories do not exist or are not accessible",
			connection: &sourcespb.GitLab{
				Credential: &sourcespb.GitLab_Token{
					Token: token,
				},
				Repositories: []string{
					"https://gitlab.com/testermctestface/testy",
					"https://gitlab.com/testermctestface/doesn't-exist",
					"https://gitlab.com/testermctestface/also-doesn't-exist",
				},
			},
			wantErrCount: 2,
		},
		{
			name: "ignore globs exclude all repos",
			connection: &sourcespb.GitLab{
				Credential: &sourcespb.GitLab_Token{
					Token: token,
				},
				IgnoreRepos: []string{
					"*",
				},
			},
			wantErrCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Source{}

			conn, err := anypb.New(tt.connection)
			if err != nil {
				t.Fatal(err)
			}

			err = s.Init(ctx, tt.name, 0, 0, false, conn, 1)
			if err != nil {
				t.Fatalf("Source.Init() error: %v", err)
			}

			errs := s.Validate(ctx)

			assert.Equal(t, tt.wantErrCount, len(errs))
		})
	}
}

func TestSource_Chunks_TargetedScan(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	secret, err := common.GetTestSecret(ctx)
	if err != nil {
		t.Fatal(fmt.Errorf("failed to access secret: %v", err))
	}

	token := secret.MustGetField("GITLAB_TOKEN")

	type init struct {
		name          string
		verify        bool
		connection    *sourcespb.GitLab
		queryCriteria *source_metadatapb.MetaData
	}
	tests := []struct {
		name       string
		init       init
		wantChunks int
	}{
		{
			name: "targeted scan; single diff",
			init: init{
				connection: &sourcespb.GitLab{Credential: &sourcespb.GitLab_Token{Token: token}},
				queryCriteria: &source_metadatapb.MetaData{
					Data: &source_metadatapb.MetaData_Gitlab{
						Gitlab: &source_metadatapb.Gitlab{
							Repository: "https://gitlab.com/testermctestface/testy.git",
							Link:       "https://gitlab.com/testermctestface/testy/blob/30c407baee70d41d062114022a59ed8ee048880a/.gitlab-ci.yml#L1",
							Commit:     "30c407baee70d41d062114022a59ed8ee048880a",
							ProjectId:  32561068,
							File:       "keys",
						},
					},
				},
			},
			wantChunks: 1,
		},
		{
			name: "targeted scan; multiple diffs",
			init: init{
				connection: &sourcespb.GitLab{Credential: &sourcespb.GitLab_Token{Token: token}},
				queryCriteria: &source_metadatapb.MetaData{
					Data: &source_metadatapb.MetaData_Gitlab{
						Gitlab: &source_metadatapb.Gitlab{
							Commit:    "b9a2fafeb0b978201e64f62efc9aa37c52a65045",
							ProjectId: 32561068,
						},
					},
				},
			},
			wantChunks: 2,
		},
		{
			name: "invalid query criteria, missing project ID",
			init: init{
				connection: &sourcespb.GitLab{Credential: &sourcespb.GitLab_Token{Token: token}},
				queryCriteria: &source_metadatapb.MetaData{
					Data: &source_metadatapb.MetaData_Gitlab{
						Gitlab: &source_metadatapb.Gitlab{
							Repository: "test_keys",
							Commit:     "fbc14303ffbf8fb1c2c1914e8dda7d0121633aca",
							File:       "not-the-file",
						},
					},
				},
			},
			wantChunks: 0,
		},
		{
			name: "invalid query criteria, missing commit",
			init: init{
				name:       "test source",
				connection: &sourcespb.GitLab{Credential: &sourcespb.GitLab_Token{Token: token}},
				queryCriteria: &source_metadatapb.MetaData{
					Data: &source_metadatapb.MetaData_Gitlab{
						Gitlab: &source_metadatapb.Gitlab{
							Repository: "test_keys",
							ProjectId:  32561068,
							File:       "not-the-file",
						},
					},
				},
			},
			wantChunks: 0,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			s := Source{}

			conn, err := anypb.New(tt.init.connection)
			assert.NoError(t, err)

			err = s.Init(ctx, tt.init.name, 0, 0, tt.init.verify, conn, 8)
			assert.NoError(t, err)

			var wg sync.WaitGroup
			chunksCh := make(chan *sources.Chunk, 1)
			wg.Add(1)
			go func() {
				defer close(chunksCh)
				defer wg.Done()
				err = s.Chunks(ctx, chunksCh, sources.ChunkingTarget{QueryCriteria: tt.init.queryCriteria})
				assert.NoError(t, err)
			}()

			i := 0
			for range chunksCh {
				i++
			}
			wg.Wait()
			assert.Equal(t, tt.wantChunks, i)
		})
	}
}

func TestSource_ChunkUnit_RepoFiltersRespected(t *testing.T) {
	ctx := context.Background()

	// Arrange: Get test environment token
	secret, err := common.GetTestSecret(ctx)
	if err != nil {
		t.Fatal(fmt.Errorf("failed to access secret: %v", err))
	}
	token := secret.MustGetField("GITLAB_TOKEN")

	// Arrange: Build a unit to scan
	unit := sources.CommonSourceUnit{
		Kind: "repo",
		ID:   "https://gitlab.com/testermctestface/testy",
	}

	tests := []struct {
		name          string
		includeRepos  []string
		ignoreRepos   []string
		wantAnyChunks bool
	}{
		{
			name:          "empty include, empty ignore",
			wantAnyChunks: true,
		},
		{
			name:          "unit matches include",
			includeRepos:  []string{"https://gitlab.com/testermctestface/testy"},
			wantAnyChunks: true,
		},
		{
			name:          "unit does not match include",
			includeRepos:  []string{"https://gitlab.com/testermctestface/something-else"},
			wantAnyChunks: false,
		},
		{
			name:          "unit matches ignore",
			ignoreRepos:   []string{"https://gitlab.com/testermctestface/testy"},
			wantAnyChunks: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange: Create the connection
			typedConn := &sourcespb.GitLab{
				Credential: &sourcespb.GitLab_Token{
					Token: token,
				},
				IncludeRepos: tt.includeRepos,
				IgnoreRepos:  tt.ignoreRepos,
			}
			conn, err := anypb.New(typedConn)
			require.NoError(t, err)

			// Arrange: Instantiate and initialize the source
			s := &Source{}
			require.NoError(t, s.Init(ctx, "test source", 1, 1, false, conn, 1))

			// Arrange: Build the chunk reporter
			chunksChan := make(chan *sources.Chunk, 1024)
			chunkReporter := sources.ChanReporter{chunksChan}

			// Act: Scan the unit
			require.NoError(t, s.ChunkUnit(ctx, unit, chunkReporter))

			// Assert: Verify that chunk production was correct
			assert.Equal(t, tt.wantAnyChunks, len(chunksChan) > 0)
		})
	}
}

func TestSource_InclusionGlobbing(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	secret, err := common.GetTestSecret(ctx)
	if err != nil {
		t.Fatal(fmt.Errorf("failed to access secret: %v", err))
	}

	token := secret.MustGetField("GITLAB_TOKEN")

	tests := []struct {
		name             string
		connection       *sourcespb.GitLab
		wantReposScanned int
		wantErrCount     int
	}{
		{
			name: "Get all Repos",
			connection: &sourcespb.GitLab{
				Credential: &sourcespb.GitLab_Token{
					Token: token,
				},
				IncludeRepos: []string{"*"},
				IgnoreRepos:  nil,
			},
			wantReposScanned: 6,
			wantErrCount:     0,
		},
		{
			name: "Ignore testy repo, include all others",
			connection: &sourcespb.GitLab{
				Credential: &sourcespb.GitLab_Token{
					Token: token,
				},
				IncludeRepos: []string{"*"},
				IgnoreRepos:  []string{"*testy*"},
			},
			wantReposScanned: 5,
			wantErrCount:     0,
		},
		{
			name: "Ignore all repos",
			connection: &sourcespb.GitLab{
				Credential: &sourcespb.GitLab_Token{
					Token: token,
				},
				IncludeRepos: nil,
				IgnoreRepos:  []string{"*"},
			},
			wantReposScanned: 0,
			wantErrCount:     0,
		},
		{
			name: "Ignore all repos, but glob doesn't compile",
			connection: &sourcespb.GitLab{
				Credential: &sourcespb.GitLab_Token{
					Token: token,
				},
				IncludeRepos: []string{
					"[",    // glob doesn't compile
					"[a-]", // glob doesn't compile
				},
				IgnoreRepos: []string{
					"*", // ignore all repos
					"[", // glob doesn't compile
				},
			},
			wantReposScanned: 0,
			wantErrCount:     3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			src := &Source{}
			conn, err := anypb.New(tt.connection)
			assert.NoError(t, err)

			err = src.Init(ctx, tt.name, 0, 0, false, conn, 1)
			assert.NoError(t, err)

			// Query GitLab for the list of configured repos.
			var repos []string
			visitor := sources.VisitorReporter{
				VisitUnit: func(ctx context.Context, unit sources.SourceUnit) error {
					id, _ := unit.SourceUnitID()
					repos = append(repos, id)
					return nil
				},
			}
			apiClient, err := src.newClient()
			assert.NoError(t, err)

			var errs []error
			ignoreRepo := buildIgnorer(src.includeRepos, src.ignoreRepos, func(err error, pattern string) {
				errs = append(errs, err)
			})
			err = src.getAllProjectRepos(ctx, apiClient, ignoreRepo, visitor)
			assert.NoError(t, err)

			assert.Equal(t, tt.wantErrCount, len(errs))
			assert.Equal(t, tt.wantReposScanned, len(repos))

		})
	}
}

func TestSource_Chunks_ProjectDetailsInChunkMetadata(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()

	secret, err := common.GetTestSecret(ctx)
	if err != nil {
		t.Fatal(fmt.Errorf("failed to access secret: %v", err))
	}

	token := secret.MustGetField("GITLAB_TOKEN")

	tests := []struct {
		name       string
		connection *sourcespb.GitLab
	}{
		{
			name: "project details in chunk metadata - No repos configured",
			connection: &sourcespb.GitLab{
				Credential: &sourcespb.GitLab_Token{
					Token: token,
				},
			},
		},
		{
			name: "project details in chunk metadata - Repo configured",
			connection: &sourcespb.GitLab{
				Credential: &sourcespb.GitLab_Token{
					Token: token,
				},
				Repositories: []string{"https://gitlab.com/testermctestface/testy.git"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			s := Source{}

			conn, err := anypb.New(tt.connection)
			if err != nil {
				t.Fatal(err)
			}

			err = s.Init(ctx, tt.name, 0, 0, false, conn, 10)
			if err != nil {
				t.Errorf("Source.Init() error = %v", err)
				return
			}
			chunksCh := make(chan *sources.Chunk, 1)
			go func() {
				defer close(chunksCh)
				err = s.Chunks(context.Background(), chunksCh)
				if err != nil {
					t.Errorf("Source.Chunks() error = %v", err)
					return
				}
			}()
			gotChunks := false
			for gotChunk := range chunksCh {
				gotChunks = true
				metadata := gotChunk.SourceMetadata.Data.(*source_metadatapb.MetaData_Gitlab)
				if metadata.Gitlab.ProjectId == 0 || metadata.Gitlab.ProjectName == "" {
					t.Errorf("Source.Chunks() missing project details in chunk metadata: %+v", metadata.Gitlab)
				}
			}
			if !gotChunks {
				t.Errorf("0 chunks scanned.")
			}
		})
	}
}

func TestSource_Enumerate_ProjectDetailsInChunkMetadata(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()

	secret, err := common.GetTestSecret(ctx)
	if err != nil {
		t.Fatal(fmt.Errorf("failed to access secret: %v", err))
	}

	token := secret.MustGetField("GITLAB_TOKEN")

	s := Source{}

	conn, err := anypb.New(&sourcespb.GitLab{
		Credential: &sourcespb.GitLab_Token{
			Token: token,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	err = s.Init(ctx, "project details in chunkmetadata", 0, 0, false, conn, 10)
	if err != nil {
		t.Errorf("Source.Init() error = %v", err)
		return
	}
	testReporter := sourcestest.TestReporter{}
	err = s.Enumerate(ctx, &testReporter)
	if err != nil {
		t.Errorf("Source.Chunks() error = %v", err)
		return
	}
	chunksCh := make(chan *sources.Chunk, 1)
	chanReporter := sources.ChanReporter{Ch: chunksCh}
	// Clear cache to force querying project details
	clear(s.repoToProjCache.cache)
	go func() {
		defer close(chunksCh)
		for _, unit := range testReporter.Units {
			err := s.ChunkUnit(context.Background(), unit, chanReporter)
			if err != nil {
				t.Errorf("Source.ChunkUnit() error = %v", err)
			}
		}
	}()
	gotChunks := false
	for gotChunk := range chunksCh {
		gotChunks = true
		metadata := gotChunk.SourceMetadata.Data.(*source_metadatapb.MetaData_Gitlab)
		if metadata.Gitlab.ProjectId == 0 || metadata.Gitlab.ProjectName == "" {
			t.Errorf("Source.Chunks() missing project details in chunk metadata: %+v", metadata.Gitlab)
		}
	}
	if !gotChunks {
		t.Errorf("0 chunks scanned.")
	}
}
