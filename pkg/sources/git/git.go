package git

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/google/go-github/v42/github"
	"golang.org/x/oauth2"
	"golang.org/x/sync/semaphore"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	diskbufferreader "github.com/trufflesecurity/disk-buffer-reader"

	"github.com/trufflesecurity/trufflehog/v3/pkg/cleantemp"
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/gitparse"
	"github.com/trufflesecurity/trufflehog/v3/pkg/handlers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sanitizer"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

const SourceType = sourcespb.SourceType_SOURCE_TYPE_GIT

type Source struct {
	name     string
	sourceId sources.SourceID
	jobId    sources.JobID
	verify   bool
	git      *Git
	sources.Progress
	conn        *sourcespb.Git
	scanOptions *ScanOptions
}

type Git struct {
	sourceType         sourcespb.SourceType
	sourceName         string
	sourceID           sources.SourceID
	jobID              sources.JobID
	sourceMetadataFunc func(file, email, commit, timestamp, repository string, line int64) *source_metadatapb.MetaData
	verify             bool
	metrics            metrics
	concurrency        *semaphore.Weighted
	skipBinaries       bool
	skipArchives       bool
}

type metrics struct {
	commitsScanned uint64
}

func NewGit(sourceType sourcespb.SourceType, jobID sources.JobID, sourceID sources.SourceID, sourceName string, verify bool, concurrency int,
	sourceMetadataFunc func(file, email, commit, timestamp, repository string, line int64) *source_metadatapb.MetaData, skipBinaries bool,
	skipArchives bool,
) *Git {
	return &Git{
		sourceType:         sourceType,
		sourceName:         sourceName,
		sourceID:           sourceID,
		jobID:              jobID,
		sourceMetadataFunc: sourceMetadataFunc,
		verify:             verify,
		concurrency:        semaphore.NewWeighted(int64(concurrency)),
		skipBinaries:       skipBinaries,
		skipArchives:       skipArchives,
	}
}

// Ensure the Source satisfies the interfaces at compile time.
var _ interface {
	sources.Source
	sources.SourceUnitEnumChunker
	sources.SourceUnitUnmarshaller
} = (*Source)(nil)

// Type returns the type of source.
// It is used for matching source types in configuration and job input.
func (s *Source) Type() sourcespb.SourceType {
	return SourceType
}

func (s *Source) SourceID() sources.SourceID {
	return s.sourceId
}

func (s *Source) JobID() sources.JobID {
	return s.jobId
}

// withScanOptions sets the scan options.
func (s *Source) withScanOptions(scanOptions *ScanOptions) {
	s.scanOptions = scanOptions
}

// Init returns an initialized GitHub source.
func (s *Source) Init(aCtx context.Context, name string, jobId sources.JobID, sourceId sources.SourceID, verify bool, connection *anypb.Any, concurrency int) error {
	s.name = name
	s.sourceId = sourceId
	s.jobId = jobId
	s.verify = verify
	if s.scanOptions == nil {
		s.scanOptions = &ScanOptions{}
	}

	var conn sourcespb.Git
	if err := anypb.UnmarshalTo(connection, &conn, proto.UnmarshalOptions{}); err != nil {
		return fmt.Errorf("error unmarshalling connection: %w", err)
	}

	if uri := conn.GetUri(); uri != "" {
		repoPath, _, err := prepareRepoSinceCommit(aCtx, uri, conn.GetBase())
		if err != nil || repoPath == "" {
			return fmt.Errorf("error preparing repo: %w", err)
		}
		conn.Directories = append(conn.Directories, repoPath)
	}

	filter, err := common.FilterFromFiles(conn.IncludePathsFile, conn.ExcludePathsFile)
	if err != nil {
		return fmt.Errorf("error creating filter: %w", err)
	}
	opts := []ScanOption{ScanOptionFilter(filter), ScanOptionLogOptions(new(git.LogOptions))}

	if depth := conn.GetMaxDepth(); depth != 0 {
		opts = append(opts, ScanOptionMaxDepth(depth))
	}
	if base := conn.GetBase(); base != "" {
		opts = append(opts, ScanOptionBaseHash(base))
	}
	if head := conn.GetHead(); head != "" {
		opts = append(opts, ScanOptionHeadCommit(head))
	}
	if globs := conn.GetExcludeGlobs(); globs != "" {
		excludedGlobs := strings.Split(globs, ",")
		opts = append(opts, ScanOptionExcludeGlobs(excludedGlobs))
	}
	if isBare := conn.GetBare(); isBare {
		opts = append(opts, ScanOptionBare(isBare))
	}
	s.withScanOptions(NewScanOptions(opts...))

	s.conn = &conn

	if concurrency == 0 {
		concurrency = runtime.NumCPU()
	}

	if err = CmdCheck(); err != nil {
		return err
	}

	s.git = NewGit(s.Type(), s.jobId, s.sourceId, s.name, s.verify, concurrency,
		func(file, email, commit, timestamp, repository string, line int64) *source_metadatapb.MetaData {
			return &source_metadatapb.MetaData{
				Data: &source_metadatapb.MetaData_Git{
					Git: &source_metadatapb.Git{
						Commit:     sanitizer.UTF8(commit),
						File:       sanitizer.UTF8(file),
						Email:      sanitizer.UTF8(email),
						Repository: sanitizer.UTF8(repository),
						Timestamp:  sanitizer.UTF8(timestamp),
						Line:       line,
					},
				},
			}
		},
		conn.GetSkipBinaries(),
		conn.GetSkipArchives(),
	)
	return nil
}

// Chunks emits chunks of bytes over a channel.
func (s *Source) Chunks(ctx context.Context, chunksChan chan *sources.Chunk, _ ...sources.ChunkingTarget) error {
	reporter := sources.ChanReporter{Ch: chunksChan}
	if err := s.scanRepos(ctx, reporter); err != nil {
		return err
	}
	if err := s.scanDirs(ctx, reporter); err != nil {
		return err
	}

	totalRepos := len(s.conn.Repositories) + len(s.conn.Directories)
	ctx.Logger().V(1).Info("Git source finished scanning", "repo_count", totalRepos)
	s.SetProgressComplete(
		totalRepos, totalRepos,
		fmt.Sprintf("Completed scanning source %s", s.name), "",
	)
	return nil
}

// scanRepos scans the configured repositories in s.conn.Repositories.
func (s *Source) scanRepos(ctx context.Context, reporter sources.ChunkReporter) error {
	if len(s.conn.Repositories) == 0 {
		return nil
	}
	totalRepos := len(s.conn.Repositories) + len(s.conn.Directories)
	for i, repoURI := range s.conn.Repositories {
		s.SetProgressComplete(i, totalRepos, fmt.Sprintf("Repo: %s", repoURI), "")
		if len(repoURI) == 0 {
			continue
		}
		if err := s.scanRepo(ctx, repoURI, reporter); err != nil {
			ctx.Logger().Info("error scanning repository", "repo", repoURI, "error", err)
			continue
		}
	}
	return nil
}

// scanRepo scans a single provided repository.
func (s *Source) scanRepo(ctx context.Context, repoURI string, reporter sources.ChunkReporter) error {
	var cloneFunc func() (string, *git.Repository, error)
	switch cred := s.conn.GetCredential().(type) {
	case *sourcespb.Git_BasicAuth:
		cloneFunc = func() (string, *git.Repository, error) {
			user := cred.BasicAuth.Username
			token := cred.BasicAuth.Password
			return CloneRepoUsingToken(ctx, token, repoURI, user)
		}
	case *sourcespb.Git_Unauthenticated:
		cloneFunc = func() (string, *git.Repository, error) {
			return CloneRepoUsingUnauthenticated(ctx, repoURI)
		}
	case *sourcespb.Git_SshAuth:
		cloneFunc = func() (string, *git.Repository, error) {
			return CloneRepoUsingSSH(ctx, repoURI)
		}
	default:
		return errors.New("invalid connection type for git source")
	}

	err := func() error {
		path, repo, err := cloneFunc()
		defer os.RemoveAll(path)
		if err != nil {
			return err
		}
		return s.git.ScanRepo(ctx, repo, path, s.scanOptions, reporter)
	}()
	if err != nil {
		return reporter.ChunkErr(ctx, err)
	}
	return nil
}

// scanDirs scans the configured directories in s.conn.Directories.
func (s *Source) scanDirs(ctx context.Context, reporter sources.ChunkReporter) error {
	totalRepos := len(s.conn.Repositories) + len(s.conn.Directories)
	for i, gitDir := range s.conn.Directories {
		s.SetProgressComplete(len(s.conn.Repositories)+i, totalRepos, fmt.Sprintf("Repo: %s", gitDir), "")

		if len(gitDir) == 0 {
			continue
		}
		if err := s.scanDir(ctx, gitDir, reporter); err != nil {
			ctx.Logger().Info("error scanning repository", "repo", gitDir, "error", err)
			continue
		}
	}
	return nil
}

// scanDir scans a single provided directory.
func (s *Source) scanDir(ctx context.Context, gitDir string, reporter sources.ChunkReporter) error {
	if !s.scanOptions.Bare && strings.HasSuffix(gitDir, "git") {
		// TODO: Figure out why we skip directories ending in "git".
		return nil
	}
	// try paths instead of url
	repo, err := RepoFromPath(gitDir, s.scanOptions.Bare)
	if err != nil {
		return reporter.ChunkErr(ctx, err)
	}

	err = func() error {
		if strings.HasPrefix(gitDir, filepath.Join(os.TempDir(), "trufflehog")) {
			defer os.RemoveAll(gitDir)
		}

		return s.git.ScanRepo(ctx, repo, gitDir, s.scanOptions, reporter)
	}()
	if err != nil {
		return reporter.ChunkErr(ctx, err)
	}
	return nil
}

func RepoFromPath(path string, isBare bool) (*git.Repository, error) {
	options := &git.PlainOpenOptions{}
	if !isBare {
		options.DetectDotGit = true
		options.EnableDotGitCommonDir = true
	}
	return git.PlainOpenWithOptions(path, options)
}

func CleanOnError(err *error, path string) {
	if *err != nil {
		os.RemoveAll(path)
	}
}

func GitURLParse(gitURL string) (*url.URL, error) {
	parsedURL, originalError := url.Parse(gitURL)
	if originalError != nil {
		var err error
		gitURLBytes := []byte("ssh://" + gitURL)
		colonIndex := bytes.LastIndex(gitURLBytes, []byte(":"))
		gitURLBytes[colonIndex] = byte('/')
		parsedURL, err = url.Parse(string(gitURLBytes))
		if err != nil {
			return nil, originalError
		}
	}
	return parsedURL, nil
}

type cloneParams struct {
	userInfo  *url.Userinfo
	gitURL    string
	args      []string
	clonePath string
}

// CloneRepo orchestrates the cloning of a given Git repository, returning its local path
// and a git.Repository object for further operations. The function sets up error handling
// infrastructure, ensuring that any encountered errors trigger a cleanup of resources.
// The core cloning logic is delegated to a nested function, which returns errors to the
// outer function for centralized error handling and cleanup.
func CloneRepo(ctx context.Context, userInfo *url.Userinfo, gitURL string, args ...string) (string, *git.Repository, error) {
	clonePath, err := cleantemp.MkdirTemp()
	if err != nil {
		return "", nil, err
	}

	repo, err := executeClone(ctx, cloneParams{userInfo, gitURL, args, clonePath})
	if err != nil {
		// DO NOT FORGET TO CLEAN UP THE CLONE PATH HERE!!
		// If we don't, we'll end up with a bunch of orphaned directories in the temp dir.
		CleanOnError(&err, clonePath)
		return "", nil, err
	}

	return clonePath, repo, nil
}

// executeClone prepares the Git URL, constructs, and executes the git clone command using the provided
// clonePath. It then opens the cloned repository, returning a git.Repository object.
func executeClone(ctx context.Context, params cloneParams) (*git.Repository, error) {
	cloneURL, err := GitURLParse(params.gitURL)
	if err != nil {
		return nil, err
	}
	if cloneURL.User == nil {
		cloneURL.User = params.userInfo
	}

	gitArgs := []string{"clone", cloneURL.String(), params.clonePath}
	gitArgs = append(gitArgs, params.args...)
	cloneCmd := exec.Command("git", gitArgs...)

	safeURL, err := stripPassword(params.gitURL)
	if err != nil {
		ctx.Logger().V(1).Info("error stripping password from git url", "error", err)
	}
	logger := ctx.Logger().WithValues(
		"subcommand", "git clone",
		"repo", safeURL,
		"path", params.clonePath,
		"args", params.args,
	)

	// Execute command and wait for the stdout / stderr.
	output, err := cloneCmd.CombinedOutput()
	if err != nil {
		err = fmt.Errorf("error executing git clone: %w", err)
	}
	logger.V(3).Info("git subcommand finished", "output", string(output))

	if cloneCmd.ProcessState == nil {
		return nil, fmt.Errorf("clone command exited with no output")
	}
	if cloneCmd.ProcessState != nil && cloneCmd.ProcessState.ExitCode() != 0 {
		logger.V(1).Info("git clone failed", "output", string(output), "error", err)
		return nil, fmt.Errorf("could not clone repo: %s, %w", safeURL, err)
	}

	options := &git.PlainOpenOptions{DetectDotGit: true, EnableDotGitCommonDir: true}
	repo, err := git.PlainOpenWithOptions(params.clonePath, options)
	if err != nil {
		return nil, fmt.Errorf("could not open cloned repo: %w", err)
	}
	logger.V(1).Info("successfully cloned repo")

	return repo, nil
}

// PingRepoUsingToken executes git ls-remote on a repo and returns any error that occurs. It can be used to validate
// that a repo actually exists and is reachable.
//
// Pinging using other authentication methods is only unimplemented because there's been no pressing need for it yet.
func PingRepoUsingToken(ctx context.Context, token, gitUrl, user string) error {
	if err := CmdCheck(); err != nil {
		return err
	}
	lsUrl, err := GitURLParse(gitUrl)
	if err != nil {
		return err
	}
	if lsUrl.User == nil {
		lsUrl.User = url.UserPassword(user, token)
	}

	// We don't actually care about any refs on the remote, we just care whether can can list them at all. So we query
	// only for a ref that we know won't exist to minimize the search time on the remote. (By default, ls-remote exits
	// with 0 even if it doesn't find any matching refs.)
	fakeRef := "TRUFFLEHOG_CHECK_GIT_REMOTE_URL_REACHABILITY"
	gitArgs := []string{"ls-remote", lsUrl.String(), "--quiet", fakeRef}
	cmd := exec.Command("git", gitArgs...)
	_, err = cmd.CombinedOutput()
	return err
}

// CloneRepoUsingToken clones a repo using a provided token.
func CloneRepoUsingToken(ctx context.Context, token, gitUrl, user string, args ...string) (string, *git.Repository, error) {
	userInfo := url.UserPassword(user, token)
	return CloneRepo(ctx, userInfo, gitUrl, args...)
}

// CloneRepoUsingUnauthenticated clones a repo with no authentication required.
func CloneRepoUsingUnauthenticated(ctx context.Context, url string, args ...string) (string, *git.Repository, error) {
	return CloneRepo(ctx, nil, url, args...)
}

// CloneRepoUsingSSH clones a repo using SSH.
func CloneRepoUsingSSH(ctx context.Context, gitURL string, args ...string) (string, *git.Repository, error) {
	if isCodeCommitURL(gitURL) {
		return CloneRepo(ctx, nil, gitURL, args...)
	}
	userInfo := url.User("git")
	return CloneRepo(ctx, userInfo, gitURL, args...)
}

var codeCommitRE = regexp.MustCompile(`ssh://git-codecommit\.[\w-]+\.amazonaws\.com`)

func isCodeCommitURL(gitURL string) bool { return codeCommitRE.MatchString(gitURL) }

func (s *Git) CommitsScanned() uint64 {
	return atomic.LoadUint64(&s.metrics.commitsScanned)
}

const gitDirName = ".git"

func (s *Git) ScanCommits(ctx context.Context, repo *git.Repository, path string, scanOptions *ScanOptions, reporter sources.ChunkReporter) error {
	// Get the remote URL for reporting (may be empty)
	remoteURL := getSafeRemoteURL(repo, "origin")
	var repoCtx context.Context
	if remoteURL != "" {
		repoCtx = context.WithValue(ctx, "repo", remoteURL)
	} else {
		repoCtx = context.WithValue(ctx, "repo", path)
	}

	commitChan, err := gitparse.NewParser().RepoPath(repoCtx, path, scanOptions.HeadHash, scanOptions.BaseHash == "", scanOptions.ExcludeGlobs, scanOptions.Bare)
	if err != nil {
		return err
	}
	if commitChan == nil {
		return nil
	}

	var depth int64
	gitDir := filepath.Join(path, gitDirName)

	logger := repoCtx.Logger()
	logger.V(1).Info("scanning repo", "base", scanOptions.BaseHash, "head", scanOptions.HeadHash)
	for commit := range commitChan {
		if len(scanOptions.BaseHash) > 0 {
			if commit.Hash == scanOptions.BaseHash {
				logger.V(1).Info("reached base commit", "commit", commit.Hash)
				break
			}
		}
		if scanOptions.MaxDepth > 0 && depth >= scanOptions.MaxDepth {
			logger.V(1).Info("reached max depth", "depth", depth)
			break
		}
		depth++
		atomic.AddUint64(&s.metrics.commitsScanned, 1)
		logger.V(5).Info("scanning commit", "commit", commit.Hash)
		for _, diff := range commit.Diffs {
			if !scanOptions.Filter.Pass(diff.PathB) {
				continue
			}

			fileName := diff.PathB
			if fileName == "" {
				continue
			}
			var email, hash, when string
			email = commit.Author
			hash = commit.Hash
			when = commit.Date.UTC().Format("2006-01-02 15:04:05 -0700")

			// Handle binary files by reading the entire file rather than using the diff.
			if diff.IsBinary {
				commitHash := plumbing.NewHash(hash)
				metadata := s.sourceMetadataFunc(fileName, email, hash, when, remoteURL, 0)
				chunkSkel := &sources.Chunk{
					SourceName:     s.sourceName,
					SourceID:       s.sourceID,
					JobID:          s.jobID,
					SourceType:     s.sourceType,
					SourceMetadata: metadata,
					Verify:         s.verify,
				}
				if err := s.handleBinary(ctx, gitDir, reporter, chunkSkel, commitHash, fileName); err != nil {
					logger.V(1).Info("error handling binary file", "error", err, "filename", fileName, "commit", commitHash, "file", diff.PathB)
				}
				continue
			}

			if diff.Content.Len() > sources.ChunkSize+sources.PeekSize {
				s.gitChunk(ctx, diff, fileName, email, hash, when, remoteURL, reporter)
				continue
			}
			metadata := s.sourceMetadataFunc(fileName, email, hash, when, remoteURL, int64(diff.LineStart))
			chunk := sources.Chunk{
				SourceName:     s.sourceName,
				SourceID:       s.sourceID,
				JobID:          s.jobID,
				SourceType:     s.sourceType,
				SourceMetadata: metadata,
				Data:           diff.Content.Bytes(),
				Verify:         s.verify,
			}
			if err := reporter.ChunkOk(ctx, chunk); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Git) gitChunk(ctx context.Context, diff gitparse.Diff, fileName, email, hash, when, urlMetadata string, reporter sources.ChunkReporter) {
	originalChunk := bufio.NewScanner(&diff.Content)
	newChunkBuffer := bytes.Buffer{}
	lastOffset := 0
	for offset := 0; originalChunk.Scan(); offset++ {
		line := make([]byte, len(originalChunk.Bytes())+1)
		copy(line, originalChunk.Bytes())
		line[len(line)-1] = byte('\n')
		if len(line) > sources.ChunkSize || len(line)+newChunkBuffer.Len() > sources.ChunkSize {
			// Add oversize chunk info
			if newChunkBuffer.Len() > 0 {
				// Send the existing fragment.
				metadata := s.sourceMetadataFunc(fileName, email, hash, when, urlMetadata, int64(diff.LineStart+lastOffset))
				chunk := sources.Chunk{
					SourceName:     s.sourceName,
					SourceID:       s.sourceID,
					JobID:          s.jobID,
					SourceType:     s.sourceType,
					SourceMetadata: metadata,
					Data:           append([]byte{}, newChunkBuffer.Bytes()...),
					Verify:         s.verify,
				}
				if err := reporter.ChunkOk(ctx, chunk); err != nil {
					// TODO: Return error.
					return
				}

				newChunkBuffer.Reset()
				lastOffset = offset
			}
			if len(line) > sources.ChunkSize {
				// Send the oversize line.
				metadata := s.sourceMetadataFunc(fileName, email, hash, when, urlMetadata, int64(diff.LineStart+offset))
				chunk := sources.Chunk{
					SourceName:     s.sourceName,
					SourceID:       s.sourceID,
					JobID:          s.jobID,
					SourceType:     s.sourceType,
					SourceMetadata: metadata,
					Data:           line,
					Verify:         s.verify,
				}
				if err := reporter.ChunkOk(ctx, chunk); err != nil {
					// TODO: Return error.
					return
				}
				continue
			}
		}

		if _, err := newChunkBuffer.Write(line); err != nil {
			ctx.Logger().Error(err, "error writing to chunk buffer", "filename", fileName, "commit", hash, "file", diff.PathB)
		}
	}
	// Send anything still in the new chunk buffer
	if newChunkBuffer.Len() > 0 {
		metadata := s.sourceMetadataFunc(fileName, email, hash, when, urlMetadata, int64(diff.LineStart+lastOffset))
		chunk := sources.Chunk{
			SourceName:     s.sourceName,
			SourceID:       s.sourceID,
			JobID:          s.jobID,
			SourceType:     s.sourceType,
			SourceMetadata: metadata,
			Data:           append([]byte{}, newChunkBuffer.Bytes()...),
			Verify:         s.verify,
		}
		if err := reporter.ChunkOk(ctx, chunk); err != nil {
			// TODO: Return error.
			return
		}
	}
}

// ScanStaged chunks staged changes.
func (s *Git) ScanStaged(ctx context.Context, repo *git.Repository, path string, scanOptions *ScanOptions, reporter sources.ChunkReporter) error {
	// Get the URL metadata for reporting (may be empty).
	urlMetadata := getSafeRemoteURL(repo, "origin")

	commitChan, err := gitparse.NewParser().Staged(ctx, path)
	if err != nil {
		return err
	}
	if commitChan == nil {
		return nil
	}

	var depth int64
	reachedBase := false
	gitDir := filepath.Join(path, gitDirName)

	ctx.Logger().V(1).Info("scanning staged changes", "path", path)
	for commit := range commitChan {
		for _, diff := range commit.Diffs {
			logger := ctx.Logger().WithValues("filename", diff.PathB, "commit", commit.Hash, "file", diff.PathB)
			logger.V(2).Info("scanning staged changes from git")

			if scanOptions.MaxDepth > 0 && depth >= scanOptions.MaxDepth {
				logger.V(1).Info("reached max depth")
				break
			}
			depth++
			if reachedBase && commit.Hash != scanOptions.BaseHash {
				break
			}
			if len(scanOptions.BaseHash) > 0 {
				if commit.Hash == scanOptions.BaseHash {
					logger.V(1).Info("reached base hash, finishing scanning files")
					reachedBase = true
				}
			}

			if !scanOptions.Filter.Pass(diff.PathB) {
				continue
			}

			fileName := diff.PathB
			if fileName == "" {
				continue
			}
			var email, hash, when string
			email = commit.Author
			hash = commit.Hash
			when = commit.Date.UTC().Format("2006-01-02 15:04:05 -0700")

			// Handle binary files by reading the entire file rather than using the diff.
			if diff.IsBinary {
				commitHash := plumbing.NewHash(hash)
				metadata := s.sourceMetadataFunc(fileName, email, "Staged", when, urlMetadata, 0)
				chunkSkel := &sources.Chunk{
					SourceName:     s.sourceName,
					SourceID:       s.sourceID,
					JobID:          s.jobID,
					SourceType:     s.sourceType,
					SourceMetadata: metadata,
					Verify:         s.verify,
				}
				if err := s.handleBinary(ctx, gitDir, reporter, chunkSkel, commitHash, fileName); err != nil {
					logger.V(1).Info("error handling binary file", "error", err, "filename", fileName)
				}
				continue
			}

			metadata := s.sourceMetadataFunc(fileName, email, "Staged", when, urlMetadata, int64(diff.LineStart))
			chunk := sources.Chunk{
				SourceName:     s.sourceName,
				SourceID:       s.sourceID,
				JobID:          s.jobID,
				SourceType:     s.sourceType,
				SourceMetadata: metadata,
				Data:           diff.Content.Bytes(),
				Verify:         s.verify,
			}
			if err := reporter.ChunkOk(ctx, chunk); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Git) ScanRepo(ctx context.Context, repo *git.Repository, repoPath string, scanOptions *ScanOptions, reporter sources.ChunkReporter) error {
	if scanOptions == nil {
		scanOptions = NewScanOptions()
	}
	if err := normalizeConfig(scanOptions, repo); err != nil {
		return err
	}
	start := time.Now().Unix()

	if err := s.ScanCommits(ctx, repo, repoPath, scanOptions, reporter); err != nil {
		return err
	}
	if !scanOptions.Bare {
		if err := s.ScanStaged(ctx, repo, repoPath, scanOptions, reporter); err != nil {
			ctx.Logger().V(1).Info("error scanning unstaged changes", "error", err)
		}
	}

	// We're logging time, but the repoPath is usually a dynamically generated folder in /tmp.
	// To make this duration logging useful, we need to log the remote as well.
	remotes, _ := repo.Remotes()
	repoURL := "Could not get remote for repo"
	if len(remotes) != 0 {
		repoURL = getSafeRemoteURL(repo, remotes[0].Config().Name)
	}

	scanTime := time.Now().Unix() - start
	ctx.Logger().V(1).Info(
		"scanning git repo complete",
		"repo", repoURL,
		"path", repoPath,
		"time_seconds", scanTime,
		"commits_scanned", atomic.LoadUint64(&s.metrics.commitsScanned),
	)
	return nil
}

// normalizeConfig updates scanOptions with the resolved base and head commit hashes.
// It's designed to handle scenarios where BaseHash and HeadHash in scanOptions might be branch names or
// other non-hash references. This ensures that both the base and head commits are resolved to actual commit hashes.
// If either commit cannot be resolved, it returns early.
// If both are resolved, it finds and sets the merge base in scanOptions.
func normalizeConfig(scanOptions *ScanOptions, repo *git.Repository) error {
	baseCommit, baseSet, err := resolveAndSetCommit(repo, &scanOptions.BaseHash)
	if err != nil {
		return err
	}

	headCommit, headSet, err := resolveAndSetCommit(repo, &scanOptions.HeadHash)
	if err != nil {
		return err
	}

	if !(baseSet && headSet) {
		return nil
	}

	// If baseCommit is an ancestor of headCommit, update c.BaseRef to be the common ancestor.
	mergeBase, err := headCommit.MergeBase(baseCommit)
	if err != nil {
		return fmt.Errorf("unable to resolve merge base: %w", err)
	}
	if len(mergeBase) == 0 {
		return fmt.Errorf("unable to resolve merge base: no merge base found")
	}

	scanOptions.BaseHash = mergeBase[0].Hash.String()

	return nil
}

// resolveAndSetCommit resolves a Git reference to a commit object and updates the reference if it was not a direct hash.
// Returns the commit object, a boolean indicating if the commit was successfully set, and any error encountered.
func resolveAndSetCommit(repo *git.Repository, ref *string) (*object.Commit, bool, error) {
	if repo == nil || ref == nil {
		return nil, false, fmt.Errorf("repo and ref must be non-nil")
	}
	if len(*ref) == 0 {
		return nil, false, nil
	}

	originalRef := *ref
	resolvedRef, err := resolveHash(repo, originalRef)
	if err != nil {
		return nil, false, fmt.Errorf("unable to resolve ref: %w", err)
	}

	commit, err := repo.CommitObject(plumbing.NewHash(resolvedRef))
	if err != nil {
		return nil, false, fmt.Errorf("unable to resolve commit: %w", err)
	}

	wasSet := originalRef != resolvedRef
	if wasSet {
		*ref = resolvedRef
	}

	return commit, wasSet, nil
}

func resolveHash(repo *git.Repository, ref string) (string, error) {
	if plumbing.IsHash(ref) {
		return ref, nil
	}

	resolved, err := TryAdditionalBaseRefs(repo, ref)
	if err != nil {
		return "", err
	}
	return resolved.String(), nil
}

func stripPassword(u string) (string, error) {
	if strings.HasPrefix(u, "git@") {
		return u, nil
	}

	repoURL, err := url.Parse(u)
	if err != nil {
		return "", fmt.Errorf("repo remote is not a URI: %w", err)
	}

	repoURL.User = nil

	return repoURL.String(), nil
}

// TryAdditionalBaseRefs looks for additional possible base refs for a repo and returns a hash if found.
func TryAdditionalBaseRefs(repo *git.Repository, base string) (*plumbing.Hash, error) {
	revisionPrefixes := []string{
		"",
		"refs/heads/",
		"refs/remotes/origin/",
	}
	for _, prefix := range revisionPrefixes {
		outHash, err := repo.ResolveRevision(plumbing.Revision(prefix + base))
		if errors.Is(err, plumbing.ErrReferenceNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		return outHash, nil
	}

	return nil, fmt.Errorf("no base refs succeeded for base: %q", base)
}

// prepareRepoSinceCommit clones a repo starting at the given commitHash and returns the cloned repo path.
func prepareRepoSinceCommit(ctx context.Context, uriString, commitHash string) (string, bool, error) {
	if commitHash == "" {
		return PrepareRepo(ctx, uriString)
	}
	// TODO: refactor with PrepareRepo to remove duplicated logic

	// The git CLI doesn't have an option to shallow clone starting at a commit
	// hash, but it does have an option to shallow clone since a timestamp. If
	// the uriString is github.com, then we query the API for the timestamp of the
	// hash and use that to clone.

	uri, err := GitURLParse(uriString)
	if err != nil {
		return "", false, fmt.Errorf("unable to parse Git URI: %s", err)
	}

	if uri.Scheme == "file" || uri.Host != "github.com" {
		return PrepareRepo(ctx, uriString)
	}

	uriPath := strings.TrimPrefix(uri.Path, "/")
	owner, repoName, found := strings.Cut(uriPath, "/")
	if !found {
		return PrepareRepo(ctx, uriString)
	}

	client := github.NewClient(nil)
	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		ts := oauth2.StaticTokenSource(
			&oauth2.Token{AccessToken: token},
		)
		tc := oauth2.NewClient(ctx, ts)
		client = github.NewClient(tc)
	}

	commit, _, err := client.Git.GetCommit(context.Background(), owner, repoName, commitHash)
	if err != nil {
		return PrepareRepo(ctx, uriString)
	}
	var timestamp string
	{
		author := commit.GetAuthor()
		if author == nil {
			return PrepareRepo(ctx, uriString)
		}
		timestamp = author.GetDate().Format(time.RFC3339)
	}

	remotePath := uri.String()
	var path string
	switch {
	case uri.User != nil:
		ctx.Logger().V(1).Info("cloning repo with authentication", "uri", uri.Redacted())
		password, ok := uri.User.Password()
		if !ok {
			return "", true, fmt.Errorf("password must be included in Git repo URL when username is provided")
		}
		path, _, err = CloneRepoUsingToken(ctx, password, remotePath, uri.User.Username(), "--shallow-since", timestamp)
		if err != nil {
			return path, true, fmt.Errorf("failed to clone authenticated Git repo (%s): %s", uri.Redacted(), err)
		}
	default:
		ctx.Logger().V(1).Info("cloning repo without authentication", "uri", uri)
		path, _, err = CloneRepoUsingUnauthenticated(ctx, remotePath, "--shallow-since", timestamp)
		if err != nil {
			return path, true, fmt.Errorf("failed to clone unauthenticated Git repo (%s): %s", remotePath, err)
		}
	}

	ctx.Logger().V(1).Info("cloned repo", "path", path)
	return path, true, nil
}

// PrepareRepo clones a repo if possible and returns the cloned repo path.
func PrepareRepo(ctx context.Context, uriString string) (string, bool, error) {
	var path string
	uri, err := GitURLParse(uriString)
	if err != nil {
		return "", false, fmt.Errorf("unable to parse Git URI: %s", err)
	}

	remote := false
	switch uri.Scheme {
	case "file":
		path = fmt.Sprintf("%s%s", uri.Host, uri.Path)
	case "http", "https":
		remotePath := uri.String()
		remote = true
		switch {
		case uri.User != nil:
			ctx.Logger().V(1).Info("cloning repo with authentication", "uri", uri.Redacted())
			password, ok := uri.User.Password()
			if !ok {
				return "", remote, fmt.Errorf("password must be included in Git repo URL when username is provided")
			}
			path, _, err = CloneRepoUsingToken(ctx, password, remotePath, uri.User.Username())
			if err != nil {
				return path, remote, fmt.Errorf("failed to clone authenticated Git repo (%s): %s", uri.Redacted(), err)
			}
		default:
			ctx.Logger().V(1).Info("cloning repo without authentication", "uri", uri)
			path, _, err = CloneRepoUsingUnauthenticated(ctx, remotePath)
			if err != nil {
				return path, remote, fmt.Errorf("failed to clone unauthenticated Git repo (%s): %s", remotePath, err)
			}
		}
	case "ssh":
		remotePath := uri.String()
		remote = true
		path, _, err = CloneRepoUsingSSH(ctx, remotePath)
		if err != nil {
			return path, remote, fmt.Errorf("failed to clone unauthenticated Git repo (%s): %s", remotePath, err)
		}
	default:
		return "", remote, fmt.Errorf("unsupported Git URI: %s", uriString)
	}

	ctx.Logger().V(1).Info("cloned repo", "path", path)
	return path, remote, nil
}

// getSafeRemoteURL is a helper function that will attempt to get a safe URL first
// from the preferred remote name, falling back to the first remote name
// available, or an empty string if there are no remotes.
func getSafeRemoteURL(repo *git.Repository, preferred string) string {
	remote, err := repo.Remote(preferred)
	if err != nil {
		var remotes []*git.Remote
		if remotes, err = repo.Remotes(); err != nil {
			return ""
		}
		if len(remotes) == 0 {
			return ""
		}
		remote = remotes[0]
	}
	// URLs is guaranteed to be non-empty
	safeURL, err := stripPassword(remote.Config().URLs[0])
	if err != nil {
		return ""
	}
	return safeURL
}

func (s *Git) handleBinary(ctx context.Context, gitDir string, reporter sources.ChunkReporter, chunkSkel *sources.Chunk, commitHash plumbing.Hash, path string) error {
	fileCtx := context.WithValues(ctx, "commit", commitHash.String(), "path", path)
	fileCtx.Logger().V(5).Info("handling binary file")

	if common.SkipFile(path) {
		fileCtx.Logger().V(5).Info("file contains ignored extension")
		return nil
	}

	if s.skipBinaries {
		fileCtx.Logger().V(5).Info("skipping binary file", "path", path)
		return nil
	}

	var handlerOpts []handlers.Option

	if s.skipArchives {
		handlerOpts = append(handlerOpts, handlers.WithSkipArchives(true))
	}

	cmd := exec.Command("git", "-C", gitDir, "cat-file", "blob", commitHash.String()+":"+path)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	fileReader, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		return err
	}
	defer func() {
		if err := fileReader.Close(); err != nil {
			ctx.Logger().Error(err, "error closing fileReader")
		}
		if err := cmd.Wait(); err != nil {
			ctx.Logger().Error(
				err, "error waiting for command",
				"command", cmd.String(),
				"stderr", stderr.String(),
				"commit", commitHash,
			)
		}
	}()

	bufferName := cleantemp.MkFilename()

	reader, err := diskbufferreader.New(fileReader, diskbufferreader.WithBufferName(bufferName))
	if err != nil {
		return err
	}
	defer reader.Close()

	if handlers.HandleFile(fileCtx, reader, chunkSkel, reporter, handlerOpts...) {
		return nil
	}

	fileCtx.Logger().V(1).Info("binary file not handled, chunking raw")
	if err := reader.Reset(); err != nil {
		return err
	}
	reader.Stop()

	chunkReader := sources.NewChunkReader()
	chunkResChan := chunkReader(fileCtx, reader)
	for data := range chunkResChan {
		chunk := *chunkSkel
		chunk.Data = data.Bytes()
		if err := data.Error(); err != nil {
			return err
		}
		if err := reporter.ChunkOk(fileCtx, chunk); err != nil {
			return err
		}
	}

	return nil
}

func (s *Source) Enumerate(ctx context.Context, reporter sources.UnitReporter) error {
	for _, repo := range s.conn.GetDirectories() {
		if repo == "" {
			continue
		}
		unit := SourceUnit{ID: repo, Kind: UnitDir}
		if err := reporter.UnitOk(ctx, unit); err != nil {
			return err
		}
	}
	for _, repo := range s.conn.GetRepositories() {
		if repo == "" {
			continue
		}
		unit := SourceUnit{ID: repo, Kind: UnitRepo}
		if err := reporter.UnitOk(ctx, unit); err != nil {
			return err
		}
	}
	return nil
}

func (s *Source) ChunkUnit(ctx context.Context, unit sources.SourceUnit, reporter sources.ChunkReporter) error {
	gitUnit, ok := unit.(SourceUnit)
	if !ok {
		return fmt.Errorf("unsupported unit type: %T", unit)
	}

	switch gitUnit.Kind {
	case UnitRepo:
		return s.scanRepo(ctx, gitUnit.ID, reporter)
	case UnitDir:
		return s.scanDir(ctx, gitUnit.ID, reporter)
	default:
		return fmt.Errorf("unexpected git unit kind: %q", gitUnit.Kind)
	}
}

func (s *Source) UnmarshalSourceUnit(data []byte) (sources.SourceUnit, error) {
	return UnmarshalUnit(data)
}
