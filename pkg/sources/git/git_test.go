package git

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kylelemons/godebug/pretty"
	"github.com/stretchr/testify/assert"
	"github.com/trufflesecurity/trufflehog/v3/pkg/feature"
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

func TestClone_Timeout(t *testing.T) {
	ctx := context.Background()

	t.Run("an unset timeout should not cause a timeout", func(t *testing.T) {
		_, _, err := CloneRepo(
			ctx,
			nil,
			"https://github.com/dustin-decker/secretsandstuff.git",
			"",
			false)

		// There shouldn't be an error - but if there is because of some other problem, we don't want this test to fail
		if err != nil {
			assert.NotContains(t, err.Error(), "timed out")
		}
	})

	t.Run("a clone that times out should time out", func(t *testing.T) {
		feature.GitCloneTimeoutDuration.Store(int64(1 * time.Nanosecond))
		t.Cleanup(func() { feature.GitCloneTimeoutDuration.Store(0) })

		_, _, err := CloneRepo(
			ctx,
			nil,
			"https://github.com/dustin-decker/secretsandstuff.git",
			"",
			false)

		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "timed out")
		}
	})
}

func TestIsRetryableCloneError(t *testing.T) {
	retryable := []string{
		// Connection reset mid-transfer.
		`could not clone repo: https://github.com/org/repo.git, error executing git clone: exit status 128, error: RPC failed; curl 56 Recv failure: Connection reset by peer
error: 7589 bytes of body are still expected
fetch-pack: unexpected disconnect while reading sideband packet
fatal: early EOF
fatal: fetch-pack: invalid index-pack output`,
		// HTTP/2 stream reset by the server.
		`could not clone repo: https://github.com/org/repo.git, error executing git clone: exit status 128, error: RPC failed; curl 92 HTTP/2 stream 7 reset by server (error 0x8 CANCEL)
error: 7457 bytes of body are still expected
fetch-pack: unexpected disconnect while reading sideband packet
fatal: early EOF
fatal: fetch-pack: invalid index-pack output`,
		// Bare 403/429 during clone matches GitHub/GitLab secondary rate
		// limiting (no accompanying auth/permission message).
		"could not clone repo: https://github.com/org/repo.git, error executing git clone: exit status 128, fatal: unable to access 'https://github.com/org/repo.git/': The requested URL returned error: 403",
		"could not clone repo: https://github.com/org/repo.git, error executing git clone: exit status 128, The requested URL returned error: 429",
		// Normal clone progress ("remote: Counting objects...") must not be
		// mistaken for a denial explanation when a later 403 is just throttling.
		`could not clone repo: https://github.com/org/repo.git, error executing git clone: exit status 128, remote: Enumerating objects: 100, done.
remote: Counting objects: 100% (100/100), done.
fatal: unable to access 'https://github.com/org/repo.git/': The requested URL returned error: 403`,
	}
	for _, msg := range retryable {
		assert.True(t, isRetryableCloneError(errors.New(msg)), "expected retryable: %q", msg)
	}

	notRetryable := []string{
		// An explicit permission-denial message, as opposed to a bare 403.
		"could not clone repo: https://github.com/org/repo.git, error executing git clone: exit status 128, remote: You are not allowed to download code from this project.",
		// The explicit denial message must win even when the combined clone
		// output also contains a literal "403" elsewhere.
		"could not clone repo: https://gitlab.com/org/repo.git, error executing git clone: exit status 128, fatal: unable to access 'https://gitlab.com/org/repo.git/': The requested URL returned error: 403\nremote: You are not allowed to download code from this project.",
		// GitHub's explicit permission-denial message, which also co-occurs
		// with a literal "403" in the combined clone output.
		"could not clone repo: https://github.com/org/repo.git, error executing git clone: exit status 128, remote: Permission to org/repo.git denied to user.\nfatal: unable to access 'https://github.com/org/repo.git/': The requested URL returned error: 403",
		// GitHub Apps/fine-grained-token variant: "Write access ... not
		// granted", also co-occurring with a literal 403.
		"could not clone repo: https://github.com/org/repo.git, error executing git clone: exit status 128, remote: Write access to repository not granted.\nfatal: unable to access 'https://github.com/org/repo.git/': The requested URL returned error: 403",
		// SAML SSO enforcement: an unrecognized "remote:" explanation
		// co-occurring with a 403, which the classifier must treat as a
		// permanent failure without needing this exact wording enumerated.
		"could not clone repo: https://github.com/org/repo.git, error executing git clone: exit status 128, remote: The organization has enabled or enforced SAML SSO.\nfatal: unable to access 'https://github.com/org/repo.git/': The requested URL returned error: 403",
		"git clone timed out (after 1h0m0s)",
		"could not clone repo: https://github.com/org/repo.git, error executing git clone: exit status 128, fatal: repository 'https://github.com/org/repo.git/' not found",
	}
	for _, msg := range notRetryable {
		assert.False(t, isRetryableCloneError(errors.New(msg)), "expected not retryable: %q", msg)
	}
	assert.False(t, isRetryableCloneError(nil))
}

func TestCreateClonePath(t *testing.T) {
	t.Run("temp dir when clonePath is empty", func(t *testing.T) {
		path, err := createClonePath("https://github.com/org/repo.git", "")
		assert.NoError(t, err)
		defer func() { _ = os.RemoveAll(path) }()

		info, err := os.Stat(path)
		assert.NoError(t, err)
		assert.True(t, info.IsDir())
		if runtime.GOOS != "windows" {
			// os.MkdirTemp guarantees 0700 so private repo contents aren't
			// exposed to other users on shared systems.
			assert.Equal(t, os.FileMode(0700), info.Mode().Perm())
		}
	})

	t.Run("temp dirs are unique across calls", func(t *testing.T) {
		// A retry replaces the previous directory; a colliding name would
		// mean cloning into a non-empty directory, which git refuses.
		first, err := createClonePath("https://github.com/org/repo.git", "")
		assert.NoError(t, err)
		defer func() { _ = os.RemoveAll(first) }()

		second, err := createClonePath("https://github.com/org/repo.git", "")
		assert.NoError(t, err)
		defer func() { _ = os.RemoveAll(second) }()

		assert.NotEqual(t, first, second)
	})

	t.Run("clonePath set builds trufflehog-<repo>-<random> subdirectory", func(t *testing.T) {
		base := t.TempDir()
		path, err := createClonePath("https://github.com/org/repo.git", base)
		assert.NoError(t, err)
		assert.Equal(t, base, filepath.Dir(path))
		// The trufflehog- prefix is what CleanTempDirsForLegacyJSON sweeps.
		assert.True(t, strings.HasPrefix(filepath.Base(path), "trufflehog-repo-"),
			"unexpected directory name %q", filepath.Base(path))

		info, err := os.Stat(path)
		assert.NoError(t, err)
		assert.True(t, info.IsDir())
		if runtime.GOOS != "windows" {
			assert.Equal(t, os.FileMode(0755), info.Mode().Perm())
		}
	})

	t.Run("repo name without .git suffix", func(t *testing.T) {
		base := t.TempDir()
		path, err := createClonePath("https://github.com/org/repo", base)
		assert.NoError(t, err)
		assert.True(t, strings.HasPrefix(filepath.Base(path), "trufflehog-repo-"),
			"unexpected directory name %q", filepath.Base(path))
	})

	t.Run("trailing slash in repo URL", func(t *testing.T) {
		base := t.TempDir()
		path, err := createClonePath("https://github.com/org/repo.git/", base)
		assert.NoError(t, err)
		assert.True(t, strings.HasPrefix(filepath.Base(path), "trufflehog-repo-"),
			"unexpected directory name %q", filepath.Base(path))
	})

	t.Run("nonexistent clonePath parents are created", func(t *testing.T) {
		base := filepath.Join(t.TempDir(), "a", "b", "c")
		path, err := createClonePath("https://github.com/org/repo.git", base)
		assert.NoError(t, err)
		assert.Equal(t, base, filepath.Dir(path))

		info, err := os.Stat(path)
		assert.NoError(t, err)
		assert.True(t, info.IsDir())
	})

	t.Run("second call with same arguments gets a fresh directory", func(t *testing.T) {
		// The retry path calls this again after RemoveAll, and concurrent
		// workers may be scanning the same repo; neither may be handed a
		// directory another caller already owns.
		base := t.TempDir()
		first, err := createClonePath("https://github.com/org/repo.git", base)
		assert.NoError(t, err)

		second, err := createClonePath("https://github.com/org/repo.git", base)
		assert.NoError(t, err)
		assert.NotEqual(t, first, second)
	})

	t.Run("error when clonePath location is not writable", func(t *testing.T) {
		// Create a *file* where the clone path should go so MkdirAll fails.
		base := filepath.Join(t.TempDir(), "blocker")
		assert.NoError(t, os.WriteFile(base, []byte("x"), 0644))

		path, err := createClonePath("https://github.com/org/repo.git", base)
		assert.Error(t, err)
		assert.Empty(t, path)
		assert.Contains(t, err.Error(), "failed to create clone path")
	})

	t.Run("distinct repos sharing a basename get distinct paths", func(t *testing.T) {
		// Only the last URL segment is used as the directory slug, so repos
		// that live under different groups but share a name collide. With
		// concurrency > 1 two workers then clone into and delete the same
		// directory, producing spurious clone errors and partial scans.
		base := t.TempDir()

		urls := []string{
			"https://gitlab.com/group-a/api.git",
			"https://gitlab.com/group-b/api.git",
			"https://gitlab.com/group-b/subgroup/api.git",
			"https://gitlab.example.com/other/api",
		}

		seen := make(map[string]string, len(urls))
		for _, u := range urls {
			path, err := createClonePath(u, base)
			assert.NoError(t, err)
			if prev, ok := seen[path]; ok {
				t.Errorf("clone path collision: %q and %q both resolve to %q", prev, u, path)
			}
			seen[path] = u
		}
	})

	t.Run("concurrent calls for the same repo get distinct paths", func(t *testing.T) {
		// The same repo can be cloned concurrently (e.g. a unit retried while
		// another worker still holds the directory). Each caller owns its
		// directory, so no two callers may be handed the same one.
		base := t.TempDir()

		const workers = 8
		var (
			mu    sync.Mutex
			paths = make(map[string]int, workers)
			wg    sync.WaitGroup
			start = make(chan struct{})
		)
		for range workers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				path, err := createClonePath("https://gitlab.com/group-a/api.git", base)
				assert.NoError(t, err)
				mu.Lock()
				paths[path]++
				mu.Unlock()
			}()
		}
		close(start)
		wg.Wait()

		assert.Len(t, paths, workers, "expected %d distinct clone paths, got %v", workers, paths)
	})
}

// TestCloneRepo_ConcurrentSameBasename reproduces the failure end to end: two
// workers cloning different repos that share a basename into a shared
// --clone-path. They are handed the same directory, so one clone fails
// ("already exists and is not an empty directory") or one worker's cleanup
// deletes the other's working tree mid-scan.
func TestCloneRepo_ConcurrentSameBasename(t *testing.T) {
	ctx := context.Background()
	clonePath := t.TempDir()

	// Two distinct source repos that both end in "api".
	sources := make([]string, 2)
	for i, group := range []string{"group-a", "group-b"} {
		repoPath := filepath.Join(t.TempDir(), group, "api")
		assert.NoError(t, os.MkdirAll(filepath.Dir(repoPath), 0755))
		assert.NoError(t, exec.Command("git", "init", repoPath).Run())
		assert.NoError(t, exec.Command("git", "-C", repoPath, "config", "user.name", "Test User").Run())
		assert.NoError(t, exec.Command("git", "-C", repoPath, "config", "user.email", "test@example.com").Run())
		assert.NoError(t, exec.Command("git", "-C", repoPath, "config", "commit.gpgsign", "false").Run())
		addTestFileAndCommit(t, repoPath, "secret.txt", "content for "+group)
		sources[i] = "file://" + repoPath
	}

	var (
		wg    sync.WaitGroup
		start = make(chan struct{})
		mu    sync.Mutex
		errs  []error
		dests = make(map[string]int)
	)
	for _, gitURL := range sources {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			path, _, err := CloneRepo(ctx, nil, gitURL, clonePath, false)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err)
				return
			}
			dests[path]++
			// Mirrors the cleanup the callers do once a repo is scanned.
			_ = os.RemoveAll(path)
		}()
	}
	close(start)
	wg.Wait()

	assert.Empty(t, errs, "concurrent clones of same-named repos should not fail")
	assert.Len(t, dests, len(sources), "each repo should clone into its own directory, got %v", dests)
}

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
				SourceType:   sourcespb.SourceType_SOURCE_TYPE_GIT,
				SourceName:   "this repo",
				SourceVerify: false,
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
				SourceType:   sourcespb.SourceType_SOURCE_TYPE_GIT,
				SourceName:   "test source",
				SourceVerify: false,
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
				SourceType:   sourcespb.SourceType_SOURCE_TYPE_GIT,
				SourceName:   "test source",
				SourceVerify: false,
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
				SourceType:   sourcespb.SourceType_SOURCE_TYPE_GIT,
				SourceName:   "test source",
				SourceVerify: false,
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
				repoPath, repo, err := CloneRepoUsingUnauthenticated(ctx, tt.repoURL, "")
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
			// Note: If we set trustLocalGitConfig to false (below), we will get an error for this test
			// b/c it's not a valid git repo and we will try to clone it.
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
		repo, b, err := PrepareRepo(ctx, tt.uri, "", true, false)
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
		_, _, _ = PrepareRepo(ctx, uri, "", false, false)
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
	t.Skip("flaky - INS-212")

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

func setupTestRepo(t *testing.T, repoName string) string {
	tempDir := t.TempDir()
	repoPath := filepath.Join(tempDir, repoName)

	assert.NoError(t, exec.Command("git", "init", repoPath).Run())
	assert.NoError(t, exec.Command("git", "-C", repoPath, "config", "user.name", "Test User").Run())
	assert.NoError(t, exec.Command("git", "-C", repoPath, "config", "user.email", "test@example.com").Run())
	assert.NoError(t, exec.Command("git", "-C", repoPath, "config", "commit.gpgsign", "false").Run())

	return repoPath
}

func addTestFileAndCommit(t *testing.T, repoPath, filename, content string) {
	testFile := filepath.Join(repoPath, filename)
	assert.NoError(t, os.WriteFile(testFile, []byte(content), 0644))
	assert.NoError(t, exec.Command("git", "-C", repoPath, "add", filename).Run())
	assert.NoError(t, exec.Command("git", "-C", repoPath, "commit", "-m", "Test commit").Run())
}

func addMaliciousGitConfig(t *testing.T, repoPath string) {
	assert.NoError(t, exec.Command("git", "-C", repoPath, "config", "alias.test", "!touch malicious_alias.txt").Run())
}

func testPrepareRepoSanitization(t *testing.T, repoPath string, trustLocalGitConfig, isBare bool) {
	ctx := context.Background()
	fileURI := "file://" + repoPath

	preparedPath, isRemote, err := PrepareRepo(ctx, fileURI, "", trustLocalGitConfig, isBare)

	assert.NoError(t, err)
	assert.False(t, isRemote, "Local file URI should not be considered remote")

	if !trustLocalGitConfig {
		assert.NotEqual(t, repoPath, preparedPath, "Sanitized repo path should be different from original")

		_, err := os.Stat(preparedPath)
		assert.NoError(t, err, "Cloned repository should exist")

		if isBare {
			_, err = os.Stat(filepath.Join(preparedPath, "refs"))
			assert.NoError(t, err, "Bare repo should have refs directory")
			_, err = os.Stat(filepath.Join(preparedPath, "HEAD"))
			assert.NoError(t, err, "Bare repo should have HEAD file")
			_, err = os.Stat(filepath.Join(preparedPath, ".git"))
			assert.True(t, os.IsNotExist(err), "Bare repo should not have .git subdirectory")
		} else {
			_, err = exec.Command("git", "-C", preparedPath, "status").Output()
			assert.NoError(t, err, "Cloned repo should be a valid git repository")
		}
	} else {
		assert.Equal(t, repoPath, preparedPath, "Trusted repo should use original path")
		output, err := exec.Command("git", "-C", preparedPath, "config", "--get", "alias.test").Output()
		assert.NoError(t, err, "Malicious git config should be present")
		assert.Equal(t, "!touch malicious_alias.txt", strings.TrimSpace(string(output)), "Malicious git config should be present")
	}
}

func TestGitConfigSanitization(t *testing.T) {
	t.Parallel()

	repoPath := setupTestRepo(t, "test-repo")
	addMaliciousGitConfig(t, repoPath)
	addTestFileAndCommit(t, repoPath, "test.txt", "test content\nsecret: AKIA1234567890123456")

	tests := []struct {
		name                string
		trustLocalGitConfig bool
	}{
		{"sanitization enabled - should clone", false},
		{"sanitization disabled - direct access", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testPrepareRepoSanitization(t, repoPath, tt.trustLocalGitConfig, false)
		})
	}
}

func TestGitConfigSanitizationWithBareRepo(t *testing.T) {
	t.Parallel()

	repoPath := setupTestRepo(t, "working-repo-original")
	addTestFileAndCommit(t, repoPath, "test.txt", "test content\nsecret: AKIA1234567890123456")

	tempDir := t.TempDir()
	bareRepoPath := filepath.Join(tempDir, "working-repo")
	assert.NoError(t, exec.Command("git", "clone", repoPath, bareRepoPath, "--bare").Run())
	addMaliciousGitConfig(t, bareRepoPath)

	tests := []struct {
		name                string
		trustLocalGitConfig bool
		isBare              bool
	}{
		{"sanitization enabled - should clone bare repo", false, true},
		{"sanitization disabled - direct access of bare repo", true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testPrepareRepoSanitization(t, bareRepoPath, tt.trustLocalGitConfig, tt.isBare)
		})
	}
}

func TestGitConfigSecurityIsolation(t *testing.T) {
	ctx := context.Background()

	maliciousRepoPath := setupTestRepo(t, "malicious-repo")
	addTestFileAndCommit(t, maliciousRepoPath, "test.txt", "test content")
	addMaliciousGitConfig(t, maliciousRepoPath)

	tests := []struct {
		name                string
		trustLocalGitConfig bool
	}{
		{"sanitized repo should be isolated from malicious config", false},
		{"trusted repo should use original path with all configs", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fileURI := "file://" + maliciousRepoPath
			preparedPath, isRemote, err := PrepareRepo(ctx, fileURI, "", tt.trustLocalGitConfig, false)

			assert.NoError(t, err)
			assert.False(t, isRemote)

			maliciousFilePath := filepath.Join(preparedPath, "malicious_alias.txt")

			if tt.trustLocalGitConfig {
				assert.Equal(t, maliciousRepoPath, preparedPath, "Trusted repo should use original path")

				output, err := exec.Command("git", "-C", preparedPath, "config", "--get", "alias.test").Output()
				assert.NoError(t, err, "Config alias.test should exist in trusted (original) repo")
				assert.Equal(t, "!touch malicious_alias.txt", strings.TrimSpace(string(output)),
					"Config alias.test should have original dangerous value")

				err = exec.Command("git", "-C", preparedPath, "test").Run()
				assert.NoError(t, err)
				_, err = os.Stat(maliciousFilePath)
				assert.False(t, os.IsNotExist(err), "Malicious file malicious_alias.txt should exist in trusted environment")

			} else {
				assert.NotEqual(t, maliciousRepoPath, preparedPath, "Sanitized repo should be different from original")

				_, err = os.Stat(preparedPath)
				assert.NoError(t, err, "Sanitized repository should exist")

				_, err = exec.Command("git", "-C", preparedPath, "status").Output()
				assert.NoError(t, err, "Sanitized repo should be a valid git repository")

				err = exec.Command("git", "-C", preparedPath, "test").Run()
				assert.Error(t, err)

				_, err = os.Stat(maliciousFilePath)
				assert.True(t, os.IsNotExist(err), "Malicious file malicious_alias.txt should not exist in sanitized environment")
			}
			// if the file exists, remove it
			if _, err := os.Stat(maliciousFilePath); err == nil {
				assert.NoError(t, os.Remove(maliciousFilePath))
			}
		})
	}
}

func TestGitConfigSanitizationWithStagedChanges(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	repoPath := setupTestRepo(t, "staged-changes-repo")
	addMaliciousGitConfig(t, repoPath)
	addTestFileAndCommit(t, repoPath, "test.txt", "test content\nsecret: AKIA1234567890123456")

	testFile := filepath.Join(repoPath, "test.txt")
	assert.NoError(t, os.WriteFile(testFile, []byte("modified content with secret: AKIA1234567890123456"), 0644))
	assert.NoError(t, exec.Command("git", "-C", repoPath, "add", "test.txt").Run())

	output, err := exec.Command("git", "-C", repoPath, "diff", "--cached").Output()
	assert.NoError(t, err)
	assert.Contains(t, string(output), "modified content", "Staged changes should exist in original repo")

	t.Run("staged changes preserved during sanitization", func(t *testing.T) {
		fileURI := "file://" + repoPath
		preparedPath, isRemote, err := PrepareRepo(ctx, fileURI, "", false, false) // Enable sanitization

		assert.NoError(t, err)
		assert.False(t, isRemote)
		assert.NotEqual(t, repoPath, preparedPath, "Sanitized repo should be cloned")

		stagedOutput, err := exec.Command("git", "-C", preparedPath, "diff", "--cached").Output()
		if err == nil && len(stagedOutput) > 0 {
			assert.Contains(t, string(stagedOutput), "modified content", "Staged changes should be preserved in cloned repo")
		}
	})
}

func TestPrepareRepoErrorPaths(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("clone failure should return error", func(t *testing.T) {
		invalidFileURI := "file:///nonexistent/invalid/repo/path"
		preparedPath, isRemote, err := PrepareRepo(ctx, invalidFileURI, "", false, false)
		assert.Error(t, err)
		assert.False(t, isRemote)
		assert.Equal(t, "", preparedPath)
	})
}

func TestResolveGitDir(t *testing.T) {
	t.Parallel()

	t.Run("regular repository with .git directory", func(t *testing.T) {
		repoPath := setupTestRepo(t, "regular-repo")
		addTestFileAndCommit(t, repoPath, "test.txt", "test content")

		gitDir, err := resolveGitDir(repoPath)
		assert.NoError(t, err)
		assert.Equal(t, filepath.Join(repoPath, ".git"), gitDir)

		// Verify it's actually a directory
		info, err := os.Stat(gitDir)
		assert.NoError(t, err)
		assert.True(t, info.IsDir())
	})

	t.Run("git worktree with .git file", func(t *testing.T) {
		// Create main repository
		mainRepoPath := setupTestRepo(t, "main-repo")
		addTestFileAndCommit(t, mainRepoPath, "test.txt", "test content")

		// Create a worktree
		worktreePath := filepath.Join(filepath.Dir(mainRepoPath), "worktree")
		err := exec.Command("git", "-C", mainRepoPath, "worktree", "add", worktreePath, "-b", "worktree-branch").Run()
		assert.NoError(t, err)

		// Verify .git is a file in the worktree
		gitPath := filepath.Join(worktreePath, ".git")
		info, err := os.Stat(gitPath)
		assert.NoError(t, err)
		assert.False(t, info.IsDir(), ".git should be a file in a worktree")

		// Test resolveGitDir
		gitDir, err := resolveGitDir(worktreePath)
		assert.NoError(t, err)
		assert.NotEqual(t, gitPath, gitDir, "resolved git dir should be different from .git file path")

		// Verify the resolved path is a valid git directory (should contain index)
		indexPath := filepath.Join(gitDir, "index")
		_, err = os.Stat(indexPath)
		assert.NoError(t, err, "resolved git dir should contain index file")
	})

	t.Run("nonexistent repository", func(t *testing.T) {
		_, err := resolveGitDir("/nonexistent/path")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to stat .git")
	})

	t.Run("invalid .git file content", func(t *testing.T) {
		tempDir := t.TempDir()
		gitPath := filepath.Join(tempDir, ".git")

		// Create an invalid .git file (not starting with "gitdir: ")
		err := os.WriteFile(gitPath, []byte("invalid content"), 0644)
		assert.NoError(t, err)

		_, err = resolveGitDir(tempDir)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid .git file format")
	})
}

func TestPrepareRepoWithWorktree(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Create main repository with staged changes
	mainRepoPath := setupTestRepo(t, "main-repo-worktree")
	addTestFileAndCommit(t, mainRepoPath, "test.txt", "initial content")

	// Create a worktree
	worktreePath := filepath.Join(filepath.Dir(mainRepoPath), "test-worktree")
	err := exec.Command("git", "-C", mainRepoPath, "worktree", "add", worktreePath, "-b", "worktree-branch").Run()
	assert.NoError(t, err)

	// Stage some changes in the worktree
	testFile := filepath.Join(worktreePath, "test.txt")
	assert.NoError(t, os.WriteFile(testFile, []byte("modified content in worktree"), 0644))
	assert.NoError(t, exec.Command("git", "-C", worktreePath, "add", "test.txt").Run())

	// Verify staged changes exist in worktree
	output, err := exec.Command("git", "-C", worktreePath, "diff", "--cached").Output()
	assert.NoError(t, err)
	assert.Contains(t, string(output), "modified content in worktree", "Staged changes should exist in worktree")

	t.Run("PrepareRepo should work with git worktree", func(t *testing.T) {
		fileURI := "file://" + worktreePath
		preparedPath, isRemote, err := PrepareRepo(ctx, fileURI, "", false, false)

		assert.NoError(t, err, "PrepareRepo should succeed with git worktree")
		assert.False(t, isRemote)
		assert.NotEmpty(t, preparedPath)

		defer func() { _ = os.RemoveAll(preparedPath) }()

		// Verify the cloned repo has the staged changes preserved
		stagedOutput, err := exec.Command("git", "-C", preparedPath, "diff", "--cached").Output()
		assert.NoError(t, err, "git diff --cached should succeed in prepared repo")
		assert.Contains(t, string(stagedOutput), "modified content in worktree",
			"Staged changes should be preserved when cloning from worktree")
	})
}

func TestNormalizeFileURI(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "absolute file URI unchanged",
			input:    "file:///absolute/path",
			expected: "",
		},
		{
			name:     "relative file URI with current directory",
			input:    "file://.",
			expected: "", // Will be set to current working directory
		},
		{
			name:     "relative file URI with subdirectory",
			input:    "file://./subdir",
			expected: "", // Will be set to current working directory + subdir
		},
		{
			name:     "relative file URI with parent directory",
			input:    "file://..",
			expected: "", // Will be set to parent of current working directory
		},
		{
			name:     "non-file URI unchanged",
			input:    "https://github.com/user/repo.git",
			expected: "https://github.com/user/repo.git",
		},
		{
			name:     "file URI with host and path",
			input:    "file://hostname/path",
			expected: "", // Will be set to absolute path of hostname/path
		},
	}

	// Get current working directory for expected results
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get current working directory: %v", err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inputURI, err := GitURLParse(tt.input)
			if err != nil {
				t.Fatalf("failed to parse input URI: %v", err)
			}

			result, err := normalizeFileURI(inputURI)
			assert.NoError(t, err)

			var expected string
			switch tt.name {
			case "absolute file URI unchanged":
				// On Windows, absolute paths get drive letter prepended
				// On Unix, they remain as-is
				if runtime.GOOS == "windows" {
					expectedPath, _ := filepath.Abs("/absolute/path")
					expected = "file://" + expectedPath
				} else {
					expected = "file:///absolute/path"
				}
			case "relative file URI with current directory":
				expected = "file://" + cwd
			case "relative file URI with subdirectory":
				expected = "file://" + filepath.Join(cwd, "subdir")
			case "relative file URI with parent directory":
				expected = "file://" + filepath.Dir(cwd)
			case "file URI with host and path":
				expectedPath, _ := filepath.Abs(filepath.Join("hostname", "path"))
				expected = "file://" + expectedPath
			default:
				expected = tt.expected
			}
			// Normalize slashes for Windows comparison
			if runtime.GOOS == "windows" {
				expected = filepath.ToSlash(expected)
			}
			assert.Equal(t, expected, result.String())
		})
	}
}

func TestPrepareRepoWithNormalization(t *testing.T) {
	repoPath := setupTestRepo(t, "test-repo")
	t.Chdir(repoPath)
	addTestFileAndCommit(t, repoPath, "test.txt", "test content")

	absoluteTests := []struct {
		name             string
		uri              string
		trustLocalConfig bool
	}{
		{
			name:             "absolute file URI - no trust",
			uri:              "file://" + repoPath,
			trustLocalConfig: false,
		},
		{
			name:             "absolute file URI - with trust",
			uri:              "file://" + repoPath,
			trustLocalConfig: true,
		},
	}

	for _, tt := range absoluteTests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			path, _, _ := PrepareRepo(ctx, tt.uri, "", tt.trustLocalConfig, false)

			if !tt.trustLocalConfig {
				assert.NotEqual(t, repoPath, path, "Cloned repo should not use original path")
				cmd := exec.Command("git", "-C", path, "status")
				err := cmd.Run()
				assert.NoError(t, err, "Cloned repo should be a valid git repository")
			} else {
				assert.Equal(t, repoPath, path, "Trusted repo should use original path")
			}

			if path != repoPath && path != "" {
				_ = os.RemoveAll(path)
			}
		})
	}

	relativeTests := []struct {
		name             string
		uri              string
		trustLocalConfig bool
	}{
		{
			name:             "relative file URI with current directory - no trust",
			uri:              "file://.",
			trustLocalConfig: false,
		},
		{
			name:             "relative file URI with current directory - with trust",
			uri:              "file://.",
			trustLocalConfig: true,
		},
	}

	for _, tt := range relativeTests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			path, _, _ := PrepareRepo(ctx, tt.uri, "", tt.trustLocalConfig, false)

			if !tt.trustLocalConfig {
				assert.NotEqual(t, tt.uri, "file://"+path, "Cloned repo should not use original path")
				cmd := exec.Command("git", "-C", path, "status")
				err := cmd.Run()
				assert.NoError(t, err, "Cloned repo should be a valid git repository")
			} else {
				assert.Equal(t, tt.uri, "file://"+path, "Trusted repo should use original path")
			}

			if path != repoPath && path != "" {
				_ = os.RemoveAll(path)
			}
		})
	}
}

func TestPrepareRepoWithNormalizationBare(t *testing.T) {
	tempDir := t.TempDir()
	t.Chdir(tempDir)

	workingRepoPath := setupTestRepo(t, "working-repo-original")
	addTestFileAndCommit(t, workingRepoPath, "test.txt", "test content")

	bareRepoPath := filepath.Join(tempDir, "bare-repo")
	assert.NoError(t, exec.Command("git", "clone", workingRepoPath, bareRepoPath, "--bare").Run())

	_, err := os.Stat(filepath.Join(bareRepoPath, "refs"))
	assert.NoError(t, err, "Bare repository should have refs directory")
	_, err = os.Stat(filepath.Join(bareRepoPath, "HEAD"))
	assert.NoError(t, err, "Bare repository should have HEAD file")

	absoluteTests := []struct {
		name             string
		uri              string
		trustLocalConfig bool
	}{
		{
			name:             "absolute file URI with bare repo - no trust",
			uri:              "file://" + bareRepoPath,
			trustLocalConfig: false,
		},
		{
			name:             "absolute file URI with bare repo - with trust",
			uri:              "file://" + bareRepoPath,
			trustLocalConfig: true,
		},
	}

	for _, tt := range absoluteTests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			path, isRemote, err := PrepareRepo(ctx, tt.uri, "", tt.trustLocalConfig, true)

			assert.NoError(t, err, "PrepareRepo should succeed")
			assert.False(t, isRemote, "File URI should not be considered remote")

			if tt.trustLocalConfig {
				assert.Equal(t, bareRepoPath, path, "Trusted bare repo should use original path")

				_, err = os.Stat(filepath.Join(path, "refs"))
				assert.NoError(t, err, "Original bare repo should have refs directory")
				_, err = os.Stat(filepath.Join(path, "HEAD"))
				assert.NoError(t, err, "Original bare repo should have HEAD file")
			} else {
				assert.NotEqual(t, bareRepoPath, path, "Sanitized bare repo path should be different from original")

				_, err = os.Stat(filepath.Join(path, "refs"))
				assert.NoError(t, err, "Cloned bare repo should have refs directory")
				_, err = os.Stat(filepath.Join(path, "HEAD"))
				assert.NoError(t, err, "Cloned bare repo should have HEAD file")
				_, err = os.Stat(filepath.Join(path, ".git"))
				assert.True(t, os.IsNotExist(err), "Bare repo should not have .git subdirectory")
			}

			if path != bareRepoPath && path != "" {
				_ = os.RemoveAll(path)
			}
		})
	}

	relativeTests := []struct {
		name             string
		uri              string
		trustLocalConfig bool
	}{
		{
			name:             "relative file URI with bare repo - no trust",
			uri:              "file://./bare-repo",
			trustLocalConfig: false,
		},
		{
			name:             "relative file URI with bare repo - with trust",
			uri:              "file://./bare-repo",
			trustLocalConfig: true,
		},
	}

	for _, tt := range relativeTests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			path, isRemote, err := PrepareRepo(ctx, tt.uri, "", tt.trustLocalConfig, true)

			assert.NoError(t, err, "PrepareRepo should succeed")
			assert.False(t, isRemote, "File URI should not be considered remote")

			if tt.trustLocalConfig {
				assert.Equal(t, tt.uri, "file://"+path, "Trusted bare repo should use relative path")

				_, err = os.Stat(filepath.Join(path, "refs"))
				assert.NoError(t, err, "Original bare repo should have refs directory")
				_, err = os.Stat(filepath.Join(path, "HEAD"))
				assert.NoError(t, err, "Original bare repo should have HEAD file")
			} else {
				assert.NotEqual(t, tt.uri, "file://"+path, "Sanitized bare repo path should be different from original")

				_, err = os.Stat(filepath.Join(path, "refs"))
				assert.NoError(t, err, "Cloned bare repo should have refs directory")
				_, err = os.Stat(filepath.Join(path, "HEAD"))
				assert.NoError(t, err, "Cloned bare repo should have HEAD file")
				_, err = os.Stat(filepath.Join(path, ".git"))
				assert.True(t, os.IsNotExist(err), "Bare repo should not have .git subdirectory")
			}

			if path != bareRepoPath && path != "" {
				_ = os.RemoveAll(path)
			}
		})
	}
}

// TestGitChunk_LongLine verifies that files containing lines longer than
// bufio's default 64 KB token limit are still scanned. Before the fix,
// bufio.Scanner would silently stop on the first oversized line and produce
// zero chunks for that file.
func TestGitChunk_LongLine(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	repoPath := setupTestRepo(t, "long-line-repo")

	// Build a single line that is 100 KB — well above the old 64 KB cap.
	longLine := strings.Repeat("a", 100*1024)
	addTestFileAndCommit(t, repoPath, "long_line.txt", longLine)

	conn, err := anypb.New(&sourcespb.Git{
		Credential: &sourcespb.Git_Unauthenticated{
			Unauthenticated: &credentialspb.Unauthenticated{},
		},
		Repositories: []string{"file://" + repoPath},
	})
	assert.NoError(t, err)

	s := Source{}
	assert.NoError(t, s.Init(ctx, "test long line", 0, 0, false, conn, 1))

	chunksCh := make(chan *sources.Chunk, 64)
	var count int
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range chunksCh {
			count++
		}
	}()

	assert.NoError(t, s.Chunks(ctx, chunksCh))
	close(chunksCh)
	wg.Wait()
	// ensure the goroutine has finished writing to count before we read it
	// one chunk for the commit/file metadata, and at least one chunk for the file content
	assert.Equal(t, 2, count, "expected two chunks from a file with a 100 KB line")
}

func TestGitLowMemoryScan(t *testing.T) {
	feature.UseGitLowMemoryScan.Store(true)
	t.Cleanup(func() { feature.UseGitLowMemoryScan.Store(false) })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	thisrepo := &sourcespb.Git{
		Directories: []string{"../../../"},
		Credential: &sourcespb.Git_Unauthenticated{
			Unauthenticated: &credentialspb.Unauthenticated{},
		},
	}
	wantChunk := &sources.Chunk{
		SourceType:   sourcespb.SourceType_SOURCE_TYPE_GIT,
		SourceName:   "this repo, low memory",
		SourceVerify: false,
	}

	s := Source{}
	conn, err := anypb.New(thisrepo)
	if err != nil {
		t.Fatal(err)
	}

	err = s.Init(ctx, "this repo, low memory", 0, 0, false, conn, 1)
	if err != nil {
		t.Errorf("Source.Init() error = %v", err)
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
	if diff := pretty.Compare(gotChunk, wantChunk); diff != "" {
		t.Errorf("Source.Chunks() UseGitLowMemoryScan diff: (-got +want)\n%s", diff)
		t.Errorf("Data: %s", string(gotChunk.Data))
	}
}

// Planted secrets for the base..head fixture. Unverifiable on purpose; the
// scan runs with verification off and we only assert they were chunked.
const (
	fixtureAWSKey      = "AKIAXYZDQCEN4B6JSJQI"
	fixtureGitHubToken = "ghp_a1B2c3D4e5F6g7H8i9J0kLmNoPqRsTuVwXyZ"
)

// mergedBaseFixture is a repository whose feature branch merged its base in,
// the shape reported in INT-1054 / CSM-2357:
//
//	F: feature work after merge      <- head
//	M: merge main into feature
//	|\
//	| C: newer base work             <- base (and the merge-base of main/feature)
//	| B: base work
//	E: more feature work             <- GitHub token
//	D: feature work                  <- AWS key
//	|/
//	A: common ancestor
//
// git log C..F is F M E D. With the customer's dates (D, E older than C) the
// pre-fix scanner stopped at C and never reached E or D.
type mergedBaseFixture struct {
	path string
	sha  map[string]string // commit letter -> full hash
}

// buildMergedBaseFixture creates the repository above with pinned committer
// dates so the ordering `git log` produces is deterministic. When
// branchNewerThanBase is true the topology is identical but D and E carry
// dates after C, which is the case the pre-fix code happened to get right;
// the fix must produce the same commit set either way. withUnreachableBase
// adds G on main after the merge, so that a base of G is not an ancestor of
// head, the shape GitHub Actions produce via pull_request.base.sha.
func buildMergedBaseFixture(t *testing.T, branchNewerThanBase, withUnreachableBase bool) mergedBaseFixture {
	t.Helper()
	f := mergedBaseFixture{path: setupTestRepo(t, "merged-base"), sha: map[string]string{}}
	git := func(args ...string) {
		t.Helper()
		out, err := exec.Command("git", append([]string{"-C", f.path}, args...)...).CombinedOutput()
		assert.NoError(t, err, "git %v: %s", args, out)
	}
	appendFile := func(name string, lines ...string) {
		t.Helper()
		fh, err := os.OpenFile(filepath.Join(f.path, name), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		assert.NoError(t, err)
		_, err = fh.WriteString(strings.Join(lines, "\n") + "\n")
		assert.NoError(t, err)
		assert.NoError(t, fh.Close())
		git("add", name)
	}
	// commit pins both dates so hashes and log ordering are reproducible.
	commit := func(letter, date, msg string) {
		t.Helper()
		cmd := exec.Command("git", "-C", f.path, "commit", "-q", "-m", msg)
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_DATE="+date, "GIT_COMMITTER_DATE="+date)
		out, err := cmd.CombinedOutput()
		assert.NoError(t, err, "commit %s: %s", letter, out)
		sha, err := exec.Command("git", "-C", f.path, "rev-parse", "HEAD").Output()
		assert.NoError(t, err)
		f.sha[letter] = strings.TrimSpace(string(sha))
	}

	// Customer dates: branch work predates the base work it later merges in.
	dates := map[string]string{
		"A": "2026-01-01T00:00:00Z",
		"D": "2026-01-02T00:00:00Z", "E": "2026-01-03T00:00:00Z",
		"B": "2026-01-04T00:00:00Z", "C": "2026-01-05T00:00:00Z",
		"M": "2026-01-06T00:00:00Z", "F": "2026-01-07T00:00:00Z", "G": "2026-01-08T00:00:00Z",
	}
	if branchNewerThanBase {
		dates["B"], dates["C"] = "2026-01-02T00:00:00Z", "2026-01-03T00:00:00Z"
		dates["D"], dates["E"] = "2026-01-04T00:00:00Z", "2026-01-05T00:00:00Z"
	}

	git("switch", "-q", "-c", "main")
	appendFile("README.md", "A")
	commit("A", dates["A"], "A: common ancestor")

	git("switch", "-q", "-c", "feature")
	appendFile("feature.txt", "D",
		"aws_access_key_id = "+fixtureAWSKey,
		"aws_secret_access_key = Tg0pz8Jii8hkLx4+PnUisM8GmKs3a2DK+9qz/lie")
	commit("D", dates["D"], "D: feature work")
	appendFile("feature.txt", "E", "github_token = "+fixtureGitHubToken)
	commit("E", dates["E"], "E: more feature work")

	git("switch", "-q", "main")
	appendFile("base.txt", "B")
	commit("B", dates["B"], "B: base work")
	appendFile("base.txt", "C")
	commit("C", dates["C"], "C: newer base work")

	git("switch", "-q", "feature")
	{
		cmd := exec.Command("git", "-C", f.path, "merge", "-q", "--no-ff", "main", "-m", "M: merge main into feature")
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_DATE="+dates["M"], "GIT_COMMITTER_DATE="+dates["M"])
		out, err := cmd.CombinedOutput()
		assert.NoError(t, err, "merge: %s", out)
		sha, err := exec.Command("git", "-C", f.path, "rev-parse", "HEAD").Output()
		assert.NoError(t, err)
		f.sha["M"] = strings.TrimSpace(string(sha))
	}
	appendFile("feature.txt", "F", "github_token = "+fixtureGitHubToken)
	commit("F", dates["F"], "F: feature work after merge")

	if withUnreachableBase {
		git("switch", "-q", "main")
		appendFile("base.txt", "G")
		commit("G", dates["G"], "G: base work after the merge")
		git("switch", "-q", "feature")
	}
	return f
}

// scanFixtureCommits runs Git.ScanRepo over the fixture with the given
// base/head and returns the set of commit hashes that produced chunks plus the
// concatenated chunk data, so callers can assert both coverage and content.
func scanFixtureCommits(t *testing.T, f mergedBaseFixture, base, head string) (map[string]bool, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	got, data, err := scanRepoRange(ctx, t, f.path, base, head)
	assert.NoError(t, err)
	return got, data
}

// scanRepoRange runs a base..head diff scan over the repository at repoPath and
// reports the commits that produced chunks, the concatenated chunk data, and
// the scan error. Callers that expect a failing scan assert on the error.
func scanRepoRange(ctx context.Context, t *testing.T, repoPath, base, head string) (map[string]bool, string, error) {
	t.Helper()

	// Open through the package's own wrapper so the test takes the same
	// path real callers do (bare detection, .git discovery).
	repo, err := RepoFromPath(repoPath)
	if err != nil {
		return nil, "", err
	}

	g := NewGit(&Config{
		SourceName:  "range fixture",
		SourceType:  sourcespb.SourceType_SOURCE_TYPE_GIT,
		Concurrency: 1,
		SourceMetadataFunc: func(info SourceMetadataInfo) *source_metadatapb.MetaData {
			return &source_metadatapb.MetaData{
				Data: &source_metadatapb.MetaData_Git{Git: &source_metadatapb.Git{Commit: info.Commit, File: info.File}},
			}
		},
	})

	chunksCh := make(chan *sources.Chunk, 64)
	scanErr := make(chan error, 1)
	go func() {
		defer close(chunksCh)
		scanErr <- g.ScanRepo(ctx, repo, repoPath, NewScanOptions(ScanOptionBaseHash(base), ScanOptionHeadCommit(head)), sources.ChanReporter{Ch: chunksCh})
	}()

	got := map[string]bool{}
	var data strings.Builder
	for c := range chunksCh {
		got[c.SourceMetadata.GetGit().GetCommit()] = true
		data.Write(c.Data)
	}
	return got, data.String(), <-scanErr
}

// TestScanRepo_BaseMergedIntoHead is the regression test for INT-1054: a
// diff scan must cover exactly `git log base..head` regardless of commit
// dates or whether base is reachable from head.
func TestScanRepo_BaseMergedIntoHead(t *testing.T) {
	// Every commit on the feature side of the range, i.e. git log C..F.
	wantScanned := []string{"F", "M", "E", "D"}
	// The merged-in base work and the common ancestor must never be scanned.
	wantSkipped := []string{"A", "B", "C"}

	cases := []struct {
		name                string
		branchNewerThanBase bool
		unreachableBase     bool
		base                string // commit letter passed as --since-commit
	}{
		{
			// The customer's reproducer: base is the main tip that was merged in,
			// and the branch commits predate it.
			name: "base is the merged-in main tip and older branch commits are skipped",
			base: "C",
		},
		{
			// GitHub Action pull_request path: base.sha has moved past the merge,
			// so normalizeConfig resolves it to the merge-base C. Must match case 1.
			name:            "base is unreachable from head",
			unreachableBase: true,
			base:            "G",
		},
		{
			// Same topology, dates flipped: pins that the result is a function of
			// the graph, not of committer dates.
			name:                "branch commits newer than the merged-in base tip",
			branchNewerThanBase: true,
			base:                "C",
		},
	}

	// Both parser strategies build their `git log` from the same args, so both
	// must agree.
	for _, lowMemory := range []bool{false, true} {
		mode := "default"
		if lowMemory {
			mode = "low-memory"
		}
		t.Run(mode, func(t *testing.T) {
			feature.UseGitLowMemoryScan.Store(lowMemory)
			t.Cleanup(func() { feature.UseGitLowMemoryScan.Store(false) })

			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					f := buildMergedBaseFixture(t, tc.branchNewerThanBase, tc.unreachableBase)
					got, data := scanFixtureCommits(t, f, f.sha[tc.base], f.sha["F"])

					for _, letter := range wantScanned {
						assert.True(t, got[f.sha[letter]], "commit %s (%s) should have been scanned; got %v", letter, f.sha[letter][:7], got)
					}
					for _, letter := range wantSkipped {
						assert.False(t, got[f.sha[letter]], "commit %s (%s) is reachable from base and must not be scanned", letter, f.sha[letter][:7])
					}
					// The secrets live in D and E, the commits the pre-fix code dropped.
					assert.Contains(t, data, fixtureAWSKey, "AWS key from commit D missing from scanned data")
					assert.Contains(t, data, fixtureGitHubToken, "GitHub token from commit E/F missing from scanned data")
				})
			}
		})
	}
}

// TestNormalizeConfig_BaseWithoutHead pins the contract that a diff scan always
// has both ends of its range by the time it reaches the parser: a base with no
// head is a scan up to the checked-out commit. Without this, the parser would
// pair ^base with --all and walk every ref not reachable from base, which is
// not what `--since-commit X` without `--branch` (the pre-commit shape) means.
func TestNormalizeConfig_BaseWithoutHead(t *testing.T) {
	// main: A; feature: A -> B, checked out. A base of main against an
	// implicit head must resolve to HEAD (B) with the merge base A.
	path := setupTestRepo(t, "base-without-head")
	addTestFileAndCommit(t, path, "a.txt", "a\n")
	runGit(t, path, "branch", "-M", "main")
	shaA := gitRevParse(t, path, "HEAD")
	runGit(t, path, "switch", "-q", "-c", "feature")
	addTestFileAndCommit(t, path, "b.txt", "b\n")
	shaB := gitRevParse(t, path, "HEAD")

	repo, err := RepoFromPath(path)
	assert.NoError(t, err)

	tests := []struct {
		name       string
		base, head string
		wantBase   string
		wantHead   string
	}{
		{
			name: "base ref and no head resolves head to HEAD",
			base: "main", wantBase: shaA, wantHead: shaB,
		},
		{
			// The pre-commit invocation: base and head are the same commit, so
			// the range is empty and only staged changes are left to scan.
			name: "base HEAD and no head is an empty range",
			base: "HEAD", wantBase: shaB, wantHead: shaB,
		},
		{
			// Full-history scans set neither end and must stay that way; an
			// implicit head here would silently narrow --all to one branch.
			name: "no base leaves head empty",
			base: "", wantBase: "", wantHead: "",
		},
		{
			name: "head without base is resolved but gets no base",
			head: "feature", wantBase: "", wantHead: shaB,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := NewScanOptions(ScanOptionBaseHash(tt.base), ScanOptionHeadCommit(tt.head))
			assert.NoError(t, normalizeConfig(opts, repo))
			assert.Equal(t, tt.wantBase, opts.BaseHash, "BaseHash")
			assert.Equal(t, tt.wantHead, opts.HeadHash, "HeadHash")
		})
	}
}

// TestScanRepo_BaseWithoutHead runs the base-without-head shape end to end on
// the merged-base fixture. The repository gets a decoy branch with its own
// planted secret that is not reachable from the checked-out feature branch;
// if the implicit head ever degrades to --all, the decoy shows up in the scan.
func TestScanRepo_BaseWithoutHead(t *testing.T) {
	const (
		decoySecret  = "ghp_DecoyBranchTokenThatMustNotBeScanned00"
		stagedSecret = "ghp_StagedTokenThatPreCommitMustStillCatch0"
	)

	// Fixture ends checked out on feature at F. Add the decoy off the common
	// ancestor and come back to feature so HEAD is F.
	build := func(t *testing.T) mergedBaseFixture {
		f := buildMergedBaseFixture(t, false, false)
		runGit(t, f.path, "switch", "-q", "-c", "decoy", f.sha["A"])
		addTestFileAndCommit(t, f.path, "decoy.txt", "github_token = "+decoySecret+"\n")
		f.sha["X"] = gitRevParse(t, f.path, "HEAD")
		runGit(t, f.path, "switch", "-q", "feature")
		return f
	}

	for _, lowMemory := range []bool{false, true} {
		mode := "default"
		if lowMemory {
			mode = "low-memory"
		}
		t.Run(mode, func(t *testing.T) {
			feature.UseGitLowMemoryScan.Store(lowMemory)
			t.Cleanup(func() { feature.UseGitLowMemoryScan.Store(false) })

			t.Run("base only scans base..HEAD", func(t *testing.T) {
				f := build(t)
				got, data := scanFixtureCommits(t, f, f.sha["C"], "")

				// Same set as an explicit head of F: git log C..F.
				for _, letter := range []string{"F", "M", "E", "D"} {
					assert.True(t, got[f.sha[letter]], "commit %s should have been scanned; got %v", letter, got)
				}
				for _, letter := range []string{"A", "B", "C", "X"} {
					assert.False(t, got[f.sha[letter]], "commit %s is outside C..HEAD and must not be scanned", letter)
				}
				assert.NotContains(t, data, decoySecret, "a commit on an unrelated branch leaked into the scan")
			})

			t.Run("pre-commit shape scans only staged changes", func(t *testing.T) {
				f := build(t)
				assert.NoError(t, os.WriteFile(filepath.Join(f.path, "staged.txt"), []byte("github_token = "+stagedSecret+"\n"), 0o644))
				runGit(t, f.path, "add", "staged.txt")

				got, data := scanFixtureCommits(t, f, "HEAD", "")

				// HEAD..HEAD is empty, so no commit in the repository may produce
				// chunks. Staged chunks carry no commit hash and are asserted on
				// through the data instead.
				for letter, sha := range f.sha {
					assert.False(t, got[sha], "commit %s was scanned but HEAD..HEAD is empty; got %v", letter, got)
				}
				assert.Contains(t, data, stagedSecret, "staged changes must still be scanned")
				assert.NotContains(t, data, decoySecret, "a commit on an unrelated branch leaked into the scan")
			})
		})
	}
}

// TestScanRepo_BaseNotUsable pins the behavior when a diff scan is given a base
// it cannot turn into a commit in the repository. Every case must fail the scan:
// the tempting alternative, degrading to a full-history scan, reports success
// for a scan that covered a different range than the user asked for, which is
// the class of silent miss INT-1054 is about.
func TestScanRepo_BaseNotUsable(t *testing.T) {
	// A syntactically valid hash that is not in any fixture below.
	const absentHash = "1111111111111111111111111111111111111111"

	tests := []struct {
		name string
		// setup returns the repo path plus the base and head to scan.
		setup   func(t *testing.T) (repoPath, base, head string)
		wantErr string
	}{
		{
			// A branch name that does not exist, e.g. a CI job passing a deleted
			// or misspelled base branch.
			name: "base ref does not exist",
			setup: func(t *testing.T) (string, string, string) {
				path := setupTestRepo(t, "unknown-ref")
				addTestFileAndCommit(t, path, "a.txt", "a\n")
				return path, "no-such-branch", gitRevParse(t, path, "HEAD")
			},
			wantErr: "unable to resolve ref",
		},
		{
			// A well-formed hash for an object the repository does not have. This
			// is what an externally shallow checkout looks like when the base is
			// older than the fetch depth.
			name: "base hash is not in the repository",
			setup: func(t *testing.T) (string, string, string) {
				path := setupTestRepo(t, "absent-hash")
				addTestFileAndCommit(t, path, "a.txt", "a\n")
				return path, absentHash, gitRevParse(t, path, "HEAD")
			},
			wantErr: "unable to resolve commit",
		},
		{
			// Two root commits: both refs resolve, but they share no history, so
			// there is no range between them to scan.
			name: "base and head have no common ancestor",
			setup: func(t *testing.T) (string, string, string) {
				path := setupTestRepo(t, "unrelated")
				addTestFileAndCommit(t, path, "a.txt", "a\n")
				base := gitRevParse(t, path, "HEAD")
				runGit(t, path, "switch", "-q", "--orphan", "unrelated")
				addTestFileAndCommit(t, path, "b.txt", "b\n")
				return path, base, gitRevParse(t, path, "HEAD")
			},
			wantErr: "merge base",
		},
		{
			// actions/checkout at its default fetch-depth: the clone holds only
			// the tip, so a base from before the cutoff is simply absent.
			name: "shallow clone does not contain the base",
			setup: func(t *testing.T) (string, string, string) {
				origin := setupTestRepo(t, "shallow-origin")
				addTestFileAndCommit(t, origin, "a.txt", "a\n")
				base := gitRevParse(t, origin, "HEAD")
				addTestFileAndCommit(t, origin, "b.txt", "b\n")

				// --depth needs a file:// URL; git ignores it for plain local paths.
				shallow := filepath.Join(t.TempDir(), "shallow")
				runGit(t, "", "clone", "-q", "--depth", "1", "file://"+origin, shallow)
				assert.False(t, gitHasObject(t, shallow, base), "fixture is not shallow: base is present")

				return shallow, base, gitRevParse(t, shallow, "HEAD")
			},
			wantErr: "unable to resolve commit",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			repoPath, base, head := tt.setup(t)
			got, _, err := scanRepoRange(ctx, t, repoPath, base, head)

			assert.ErrorContains(t, err, tt.wantErr)
			assert.Empty(t, got, "a scan that cannot resolve its base must not fall back to scanning commits")
		})
	}
}

// TestScanRepo_ShallowClone pins where the graft boundary of a shallow clone
// starts to matter for a diff scan. git itself handles a truncated history
// fine, so the boundary that counts is the one go-git needs to walk in
// normalizeConfig: MergeBase loads a commit's parents before it can recognize
// the commit as the range boundary (bfsCommitIterator.Next), so a base sitting
// on the graft has no resolvable merge base.
//
// Both behaviors below predate the base..head range change; normalizeConfig is
// not part of it. See https://github.com/trufflesecurity/trufflehog/issues/4895
// for the same failure surfacing on GitLab.
func TestScanRepo_ShallowClone(t *testing.T) {
	// A fixture deep enough that a clone can keep the base and still cut the
	// history off somewhere above it.
	newOrigin := func(t *testing.T) string {
		origin := setupTestRepo(t, "shallow-origin")
		for _, f := range []string{"a.txt", "b.txt", "c.txt", "d.txt"} {
			addTestFileAndCommit(t, origin, f, f+"\n")
		}
		return origin
	}
	clone := func(t *testing.T, origin, depth string) string {
		// --depth needs a file:// URL; git ignores it for plain local paths.
		path := filepath.Join(t.TempDir(), "shallow")
		runGit(t, "", "clone", "-q", "--depth", depth, "file://"+origin, path)
		return path
	}

	t.Run("base is the graft boundary", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Depth 2 keeps the tip and the base; the base's parent is cut off,
		// which is the shape --shallow-since produces for its own base commit.
		shallow := clone(t, newOrigin(t), "2")
		head, base := gitRevParse(t, shallow, "HEAD"), gitRevParse(t, shallow, "HEAD~1")
		assert.False(t, gitHasObject(t, shallow, base+"^"), "fixture is wrong: the base's parent is present")

		got, _, err := scanRepoRange(ctx, t, shallow, base, head)

		assert.ErrorContains(t, err, "unable to resolve merge base")
		assert.Empty(t, got, "an unresolvable merge base must fail the scan, not scan an arbitrary range")
	})

	t.Run("base is above the graft boundary", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// One more commit of depth is all it takes: the base's parent is present,
		// so the merge base resolves and git scans the range over a history it
		// cannot fully walk.
		shallow := clone(t, newOrigin(t), "3")
		head, base := gitRevParse(t, shallow, "HEAD"), gitRevParse(t, shallow, "HEAD~1")
		assert.True(t, gitHasObject(t, shallow, base+"^"), "fixture is wrong: the base's parent is missing")

		got, _, err := scanRepoRange(ctx, t, shallow, base, head)

		assert.NoError(t, err)
		assert.True(t, got[head], "the one commit in base..head should have been scanned; got %v", got)
		assert.False(t, got[base], "the base is excluded from its own range")
	})
}

// runGit runs a git command, failing the test on error. An empty repoPath runs
// git outside any repository, which clone needs.
func runGit(t *testing.T, repoPath string, args ...string) {
	t.Helper()
	if repoPath != "" {
		args = append([]string{"-C", repoPath}, args...)
	}
	out, err := exec.Command("git", args...).CombinedOutput()
	assert.NoError(t, err, "git %v: %s", args, out)
}

func gitRevParse(t *testing.T, repoPath, rev string) string {
	t.Helper()
	out, err := exec.Command("git", "-C", repoPath, "rev-parse", rev).Output()
	assert.NoError(t, err)
	return strings.TrimSpace(string(out))
}

// gitHasObject reports whether the repository holds the commit named by rev,
// used to confirm where a shallow fixture's graft boundary actually landed
// before asserting on behavior that depends on it.
func gitHasObject(t *testing.T, repoPath, rev string) bool {
	t.Helper()
	return exec.Command("git", "-C", repoPath, "cat-file", "-e", rev+"^{commit}").Run() == nil
}
