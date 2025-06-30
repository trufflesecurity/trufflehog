package git

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/kylelemons/godebug/pretty"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/credentialspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/process"
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
	basicUser := secret.MustGetField("GITLAB_USER")
	basicPass := secret.MustGetField("GITLAB_PASS")

	type init struct {
		name        string
		verify      bool
		connection  *sourcespb.Git
		concurrency int
	}
	tests := []struct {
		name      string
		init      init
		wantChunk *sources.Chunk
		wantErr   bool
	}{
		{
			name: "local repo",
			init: init{
				name: "this repo",
				connection: &sourcespb.Git{
					Directories: []string{"../../../"},
					Credential: &sourcespb.Git_Unauthenticated{
						Unauthenticated: &credentialspb.Unauthenticated{},
					},
				},
				concurrency: 4,
			},
			wantChunk: &sources.Chunk{
				SourceType: sourcespb.SourceType_SOURCE_TYPE_GIT,
				SourceName: "this repo",
				Verify:     false,
			},
			wantErr: false,
		},
		{
			name: "remote repo, unauthenticated",
			init: init{
				name: "test source",
				connection: &sourcespb.Git{
					Repositories: []string{"https://github.com/dustin-decker/secretsandstuff.git"},
					Credential: &sourcespb.Git_Unauthenticated{
						Unauthenticated: &credentialspb.Unauthenticated{},
					},
				},
				concurrency: 4,
			},
			wantChunk: &sources.Chunk{
				SourceType: sourcespb.SourceType_SOURCE_TYPE_GIT,
				SourceName: "test source",
				Verify:     false,
			},
			wantErr: false,
		},
		{
			name: "remote repo, unauthenticated, concurrency 0",
			init: init{
				name: "test source",
				connection: &sourcespb.Git{
					Repositories: []string{"https://github.com/dustin-decker/secretsandstuff.git"},
					Credential: &sourcespb.Git_Unauthenticated{
						Unauthenticated: &credentialspb.Unauthenticated{},
					},
				},
				concurrency: 0,
			},
			wantChunk: &sources.Chunk{
				SourceType: sourcespb.SourceType_SOURCE_TYPE_GIT,
				SourceName: "test source",
				Verify:     false,
			},
			wantErr: false,
		},
		{
			name: "remote repo, basic auth",
			init: init{
				name: "test source",
				connection: &sourcespb.Git{
					Repositories: []string{"https://github.com/dustin-decker/secretsandstuff.git"},
					Credential: &sourcespb.Git_BasicAuth{
						BasicAuth: &credentialspb.BasicAuth{
							Username: basicUser,
							Password: basicPass,
						},
					},
				},
				concurrency: 4,
			},
			wantChunk: &sources.Chunk{
				SourceType: sourcespb.SourceType_SOURCE_TYPE_GIT,
				SourceName: "test source",
				Verify:     false,
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

			err = s.Init(ctx, tt.init.name, 0, 0, tt.init.verify, conn, tt.init.concurrency)
			if (err != nil) != tt.wantErr {
				t.Errorf("Source.Init() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			chunksCh := make(chan *sources.Chunk, 1)
			go func() {
				assert.NoError(t, s.Chunks(ctx, chunksCh))
			}()
			gotChunk := <-chunksCh
			gotChunk.Data = nil
			// Commits don't come in a deterministic order, so remove metadata comparison
			gotChunk.SourceMetadata = nil
			if diff := pretty.Compare(gotChunk, tt.wantChunk); diff != "" {
				t.Errorf("Source.Chunks() %s diff: (-got +want)\n%s", tt.name, diff)
				t.Errorf("Data: %s", string(gotChunk.Data))
			}
		})
	}
}

// We ran into an issue where upgrading a dependency caused the git patch chunking to break
// So this test exists to make sure that when something changes, we know about it.
func TestSource_Chunks_Integration(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type init struct {
		name       string
		verify     bool
		connection *sourcespb.Git
	}

	type byteCompare struct {
		B     []byte
		Found bool
		Multi bool
	}
	tests := []struct {
		name string
		init init
		// verified
		repoURL           string
		expectedChunkData map[string]*byteCompare
		scanOptions       ScanOptions
	}{
		{
			name:    "remote repo, unauthenticated",
			repoURL: "https://github.com/dustin-decker/secretsandstuff.git",
			expectedChunkData: map[string]*byteCompare{
				"70001020fab32b1fcf2f1f0e5c66424eae649826-":     {B: []byte("Dustin Decker <humanatcomputer@gmail.com>\nGitHub <noreply@github.com>\nUpdate aws\n")},
				"70001020fab32b1fcf2f1f0e5c66424eae649826-aws":  {B: []byte("[default]\naws_access_key_id = AKIAXYZDQCEN4B6JSJQI\naws_secret_access_key = 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\noutput = json\nregion = us-east-2\n")},
				"a6f8aa55736d4a85be31a0048a4607396898647a-":     {B: []byte("Dustin Decker <dustindecker@protonmail.com>\nGitHub <noreply@github.com>\nUpdate bump\n")},
				"a6f8aa55736d4a85be31a0048a4607396898647a-bump": {B: []byte("\n\nf\n")},
				"73ab4713057944753f1bdeb80e757380e64c6b5b-":     {B: []byte("Dustin <dustindecker@protonmail.com>\nDustin <dustindecker@protonmail.com>\nbump\n")},
				"73ab4713057944753f1bdeb80e757380e64c6b5b-bump": {B: []byte(" s \n\n")},
				"2f251b8c1e72135a375b659951097ec7749d4af9-":     {B: []byte("Dustin <dustindecker@protonmail.com>\nDustin <dustindecker@protonmail.com>\nbump\n")},
				"2f251b8c1e72135a375b659951097ec7749d4af9-bump": {B: []byte(" \n\n")},
				"e6c8bbabd8796ea3cd85bfc2e55b27e0a491747f-":     {B: []byte("Dustin Decker <dustindecker@protonmail.com>\nGitHub <noreply@github.com>\nUpdate bump\n")},
				"e6c8bbabd8796ea3cd85bfc2e55b27e0a491747f-bump": {B: []byte("\noops \n")},
				"735b52b0eb40610002bb1088e902bd61824eb305-":     {B: []byte("Dustin Decker <dustindecker@protonmail.com>\nGitHub <noreply@github.com>\nUpdate bump\n")},
				"735b52b0eb40610002bb1088e902bd61824eb305-bump": {B: []byte("\noops\n")},
				"ce62d79908803153ef6e145e042d3e80488ef747-":     {B: []byte("Dustin Decker <dustindecker@protonmail.com>\nGitHub <noreply@github.com>\nCreate bump\n")},
				"ce62d79908803153ef6e145e042d3e80488ef747-bump": {B: []byte("\n")},
				// Normally we might expect to see this commit, and we may in the future.
				// But at the moment we're ignoring any commit unless it contains at least one non-space character.
				"27fbead3bf883cdb7de9d7825ed401f28f9398f1-":      {B: []byte("Dustin <dustindecker@protonmail.com>\nDustin <dustindecker@protonmail.com>\noops\n")},
				"27fbead3bf883cdb7de9d7825ed401f28f9398f1-slack": {B: []byte("\n\n\nyup, just did that\n\ngithub_lol: \"ffc7e0f9400fb6300167009e42d2f842cd7956e2\"\n\noh, goodness. there's another one!\n")},
				"8afb0ecd4998b1179e428db5ebbcdc8221214432-":      {B: []byte("Dustin <dustindecker@protonmail.com>\nDustin <dustindecker@protonmail.com>\nadd slack token\n")},
				"8afb0ecd4998b1179e428db5ebbcdc8221214432-slack": {B: []byte("oops might drop a slack token here\n\ngithub_secret=\"369963c1434c377428ca8531fbc46c0c43d037a0\"\n\nyup, just did that\n"), Multi: true},
				"8fe6f04ef1839e3fc54b5147e3d0e0b7ab971bd5-":      {B: []byte("Dustin <dustindecker@protonmail.com>\nDustin <dustindecker@protonmail.com>\noops, accidently commited AWS token...\n")}, //nolint:misspell
				"8fe6f04ef1839e3fc54b5147e3d0e0b7ab971bd5-aws":   {B: []byte("blah blaj\n\nthis is the secret: AKIA2E0A8F3B244C9986\n\nokay thank you bye\n"), Multi: true},
				"84e9c75e388ae3e866e121087ea2dd45a71068f2-":      {B: []byte("Dylan Ayrey <dxa4481@rit.edu>\nGitHub <noreply@github.com>\nUpdate aws\n")},
				"84e9c75e388ae3e866e121087ea2dd45a71068f2-aws":   {B: []byte("\n\nthis is the secret: [Default]\nAccess key Id: AKIAILE3JG6KMS3HZGCA\nSecret Access Key: 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\n\nokay thank you bye\n"), Multi: false},
			},
		},
		{
			name:    "remote repo, limited",
			repoURL: "https://github.com/dustin-decker/secretsandstuff.git",
			expectedChunkData: map[string]*byteCompare{
				"70001020fab32b1fcf2f1f0e5c66424eae649826-":    {B: []byte("Dustin Decker <humanatcomputer@gmail.com>\nGitHub <noreply@github.com>\nUpdate aws\n")},
				"70001020fab32b1fcf2f1f0e5c66424eae649826-aws": {B: []byte("[default]\naws_access_key_id = AKIAXYZDQCEN4B6JSJQI\naws_secret_access_key = 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\noutput = json\nregion = us-east-2\n")},
			},
			scanOptions: ScanOptions{
				HeadHash: "70001020fab32b1fcf2f1f0e5c66424eae649826",
				BaseHash: "a6f8aa55736d4a85be31a0048a4607396898647a",
			},
		},
		{
			name:    "remote repo, main ahead of branch",
			repoURL: "https://github.com/bill-rich/bad-secrets.git",
			expectedChunkData: map[string]*byteCompare{
				"547865c6cc0da46622306902b1b66f7e25dd0412-":                 {B: []byte("bill-rich <bill.rich@gmail.com>\nbill-rich <bill.rich@gmail.com>\nAdd some_branch_file\n")},
				"547865c6cc0da46622306902b1b66f7e25dd0412-some_branch_file": {B: []byte("[default]\naws_access_key=AKIAYVP4CIPPH5TNP3SW\naws_secret_access_key=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\nregion=us-east-2\noutput=json\n\n#addibng a comment\n")},
			},
			scanOptions: ScanOptions{
				HeadHash: "some_branch",
				BaseHash: "master",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Source{}

			beforeProcesses := process.GetGitProcessList()

			conn, err := anypb.New(tt.init.connection)
			if err != nil {
				t.Fatal(err)
			}
			err = s.Init(ctx, tt.init.name, 0, 0, tt.init.verify, conn, 4)
			if err != nil {
				t.Fatal(err)
			}
			chunksCh := make(chan *sources.Chunk, 1)
			go func() {
				defer close(chunksCh)
				repoPath, repo, err := CloneRepoUsingUnauthenticated(ctx, tt.repoURL)
				if err != nil {
					panic(err)
				}
				err = s.git.ScanRepo(ctx, repo, repoPath, &tt.scanOptions, sources.ChanReporter{Ch: chunksCh})
				if err != nil {
					panic(err)
				}
			}()

			for chunk := range chunksCh {
				key := ""
				switch meta := chunk.SourceMetadata.GetData().(type) {
				case *source_metadatapb.MetaData_Git:
					key = strings.TrimRight(meta.Git.Commit+"-"+meta.Git.File, "\n")
				}

				if expectedData, exists := tt.expectedChunkData[key]; !exists {
					t.Errorf("A chunk exists that was not expected with key %q", key)
				} else {
					if bytes.Equal(chunk.Data, expectedData.B) {
						(*tt.expectedChunkData[key]).Found = true
					} else if !expectedData.Multi {
						t.Errorf("Got %q: %q, which was not expected", key, string(chunk.Data))
					}
				}
			}

			for key, expected := range tt.expectedChunkData {
				if !expected.Found {
					t.Errorf("Expected data with key %q not found", key)
				}

			}

			afterProcesses := process.GetGitProcessList()
			zombies := process.DetectGitZombies(beforeProcesses, afterProcesses)
			if len(zombies) > 0 {
				t.Errorf("Git zombies detected: %v", zombies)
			}
		})
	}
}

func TestSource_Chunks_Edge_Cases(t *testing.T) {

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	secret, err := common.GetTestSecret(ctx)
	if err != nil {
		t.Fatal(fmt.Errorf("failed to access secret: %v", err))
	}
	basicUser := secret.MustGetField("GITLAB_USER")
	basicPass := secret.MustGetField("GITLAB_PASS")

	type init struct {
		name       string
		verify     bool
		connection *sourcespb.Git
	}
	tests := []struct {
		name    string
		init    init
		wantErr string
	}{
		{
			name: "empty repo",
			init: init{
				name: "test source",
				connection: &sourcespb.Git{
					Repositories: []string{"https://github.com/git-fixtures/empty.git"},
					Credential: &sourcespb.Git_Unauthenticated{
						Unauthenticated: &credentialspb.Unauthenticated{},
					},
				},
			},
			wantErr: "remote",
		},
		{
			name: "no repo",
			init: init{
				name: "test source",
				connection: &sourcespb.Git{
					Repositories: []string{""},
					Credential: &sourcespb.Git_Unauthenticated{
						Unauthenticated: &credentialspb.Unauthenticated{},
					},
				},
			},
			wantErr: "remote",
		},
		{
			name: "no repo, basic auth",
			init: init{
				name: "test source",
				connection: &sourcespb.Git{
					Repositories: []string{""},
					Credential: &sourcespb.Git_BasicAuth{
						BasicAuth: &credentialspb.BasicAuth{
							Username: basicUser,
							Password: basicPass,
						},
					},
				},
			},
			wantErr: "remote",
		},
		{
			name: "symlinks repo",
			init: init{
				name: "test source",
				connection: &sourcespb.Git{
					Repositories: []string{"https://github.com/git-fixtures/symlinks.git"},
					Credential: &sourcespb.Git_Unauthenticated{
						Unauthenticated: &credentialspb.Unauthenticated{},
					},
				},
			},
		},
		{
			name: "submodule repo",
			init: init{
				name: "test source",
				connection: &sourcespb.Git{
					Repositories: []string{"https://github.com/git-fixtures/submodule.git"},
					Credential: &sourcespb.Git_Unauthenticated{
						Unauthenticated: &credentialspb.Unauthenticated{},
					},
				},
			},
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
			if err != nil {
				t.Errorf("Source.Init() error = %v", err)
				return
			}
			chunksCh := make(chan *sources.Chunk, 1)
			go func() {
				for chunk := range chunksCh {
					chunk.Data = nil
				}

			}()
			if err := s.Chunks(ctx, chunksCh); err != nil && !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Source.Chunks() error = %v, wantErr %v", err, tt.wantErr)
			}

		})
	}
}

func TestPrepareRepo(t *testing.T) {
	tests := []struct {
		uri    string
		path   bool
		remote bool
		err    error
	}{
		{
			uri:    "https://github.com/dustin-decker/secretsandstuff.git",
			path:   true,
			remote: true,
			err:    nil,
		},
		{
			uri:    "http://github.com/dustin-decker/secretsandstuff.git",
			path:   true,
			remote: true,
			err:    nil,
		},
		{
			uri:    "file:///path/to/file.json",
			path:   true,
			remote: false,
			err:    nil,
		},
		{
			uri:    "no bueno",
			path:   false,
			remote: false,
			err:    fmt.Errorf("unsupported Git URI: no bueno"),
		},
	}

	for _, tt := range tests {
		ctx := context.Background()
		repo, b, err := PrepareRepo(ctx, tt.uri)
		var repoLen bool
		if len(repo) > 0 {
			repoLen = true
		} else {
			repoLen = false
		}
		if repoLen != tt.path || b != tt.remote {
			t.Errorf("PrepareRepo(%v) got: %v, %v, %v want: %v, %v, %v", tt.uri, repo, b, err, tt.path, tt.remote, tt.err)
		}
	}
}

func BenchmarkPrepareRepo(b *testing.B) {
	uri := "https://github.com/dustin-decker/secretsandstuff.git"
	ctx := context.Background()
	for i := 0; i < b.N; i++ {
		_, _, _ = PrepareRepo(ctx, uri)
	}
}

func TestGitURLParse(t *testing.T) {
	for _, tt := range []struct {
		url      string
		host     string
		user     string
		password string
		port     string
		path     string
		scheme   string
	}{
		{
			"https://user@github.com/org/repo",
			"github.com",
			"user",
			"",
			"",
			"/org/repo",
			"https",
		},
		{
			"https://user:pass@github.com/org/repo",
			"github.com",
			"user",
			"pass",
			"",
			"/org/repo",
			"https",
		},
		{
			"ssh://user@github.com/org/repo",
			"github.com",
			"user",
			"",
			"",
			"/org/repo",
			"ssh",
		},
		{
			"user@github.com:org/repo",
			"github.com",
			"user",
			"",
			"",
			"/org/repo",
			"ssh",
		},
	} {
		u, err := GitURLParse(tt.url)
		if err != nil {
			t.Fatal(err)
		}
		assert.Equal(t, tt.host, u.Host)
		assert.Equal(t, tt.user, u.User.Username())
		password, _ := u.User.Password()
		assert.Equal(t, tt.password, password)
		assert.Equal(t, tt.port, u.Port())
		assert.Equal(t, tt.path, u.Path)
		assert.Equal(t, tt.scheme, u.Scheme)
	}
}

func TestEnumerate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Setup the connection to test enumeration.
	units := []string{
		"foo", "bar", "baz",
		"/path/to/dir/", "/path/to/another/dir/",
	}
	conn, err := anypb.New(&sourcespb.Git{
		Repositories: units[0:3],
		Directories:  units[3:],
	})
	assert.NoError(t, err)

	// Initialize the source.
	s := Source{}
	err = s.Init(ctx, "test enumerate", 0, 0, true, conn, 1)
	assert.NoError(t, err)

	reporter := sourcestest.TestReporter{}
	err = s.Enumerate(ctx, &reporter)
	assert.NoError(t, err)

	assert.Equal(t, len(units), len(reporter.Units))
	assert.Equal(t, 0, len(reporter.UnitErrs))
	for _, unit := range reporter.Units {
		id, _ := unit.SourceUnitID()
		assert.Contains(t, units, id)
	}
	for _, unit := range units[:3] {
		assert.Contains(t, reporter.Units, SourceUnit{ID: unit, Kind: UnitRepo})
	}
	for _, unit := range units[3:] {
		assert.Contains(t, reporter.Units, SourceUnit{ID: unit, Kind: UnitDir})
	}
}

func TestChunkUnit(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	// Initialize the source.
	s := Source{}
	conn, err := anypb.New(&sourcespb.Git{
		Credential: &sourcespb.Git_Unauthenticated{},
	})
	assert.NoError(t, err)
	err = s.Init(ctx, "test chunk", 0, 0, true, conn, 1)
	assert.NoError(t, err)

	reporter := sourcestest.TestReporter{}

	// Happy path single repository.
	err = s.ChunkUnit(ctx, SourceUnit{
		ID:   "https://github.com/dustin-decker/secretsandstuff.git",
		Kind: UnitRepo,
	}, &reporter)
	assert.NoError(t, err)

	// Error path - should return fatal error for missing directory.
	err = s.ChunkUnit(ctx, SourceUnit{
		ID:   "/file/not/found",
		Kind: UnitDir,
	}, &reporter)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "directory does not exist")

	assert.Equal(t, 22, len(reporter.Chunks))
	assert.Equal(t, 0, len(reporter.ChunkErrs))
}
