package git

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	diskbufferreader "github.com/bill-rich/disk-buffer-reader"
	"github.com/go-errors/errors"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/google/go-github/v42/github"
	"golang.org/x/oauth2"
	"golang.org/x/sync/semaphore"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/gitparse"
	"github.com/trufflesecurity/trufflehog/v3/pkg/handlers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sanitizer"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

type Source struct {
	name     string
	sourceId int64
	jobId    int64
	verify   bool
	git      *Git
	sources.Progress
	conn *sourcespb.Git
}

type Git struct {
	sourceType         sourcespb.SourceType
	sourceName         string
	sourceID           int64
	jobID              int64
	sourceMetadataFunc func(file, email, commit, timestamp, repository string, line int64) *source_metadatapb.MetaData
	verify             bool
	concurrency        *semaphore.Weighted
}

func NewGit(sourceType sourcespb.SourceType, jobID, sourceID int64, sourceName string, verify bool, concurrency int,
	sourceMetadataFunc func(file, email, commit, timestamp, repository string, line int64) *source_metadatapb.MetaData,
) *Git {
	return &Git{
		sourceType:         sourceType,
		sourceName:         sourceName,
		sourceID:           sourceID,
		jobID:              jobID,
		sourceMetadataFunc: sourceMetadataFunc,
		verify:             verify,
		concurrency:        semaphore.NewWeighted(int64(concurrency)),
	}
}

// Ensure the Source satisfies the interface at compile time.
var _ sources.Source = (*Source)(nil)

// Type returns the type of source.
// It is used for matching source types in configuration and job input.
func (s *Source) Type() sourcespb.SourceType {
	return sourcespb.SourceType_SOURCE_TYPE_GIT
}

func (s *Source) SourceID() int64 {
	return s.sourceId
}

func (s *Source) JobID() int64 {
	return s.jobId
}

// Init returns an initialized GitHub source.
func (s *Source) Init(aCtx context.Context, name string, jobId, sourceId int64, verify bool, connection *anypb.Any, concurrency int) error {

	s.name = name
	s.sourceId = sourceId
	s.jobId = jobId
	s.verify = verify

	var conn sourcespb.Git
	if err := anypb.UnmarshalTo(connection, &conn, proto.UnmarshalOptions{}); err != nil {
		return errors.WrapPrefix(err, "error unmarshalling connection", 0)
	}

	s.conn = &conn

	if concurrency == 0 {
		concurrency = runtime.NumCPU()
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
		})
	return nil
}

// Chunks emits chunks of bytes over a channel.
func (s *Source) Chunks(ctx context.Context, chunksChan chan *sources.Chunk) error {
	// TODO: refactor to remove duplicate code
	totalRepos := len(s.conn.Repositories) + len(s.conn.Directories)
	switch cred := s.conn.GetCredential().(type) {
	case *sourcespb.Git_BasicAuth:
		user := cred.BasicAuth.Username
		token := cred.BasicAuth.Password

		for i, repoURI := range s.conn.Repositories {
			s.SetProgressComplete(i, totalRepos, fmt.Sprintf("Repo: %s", repoURI), "")
			if len(repoURI) == 0 {
				continue
			}
			err := func(repoURI string) error {
				path, repo, err := CloneRepoUsingToken(ctx, token, repoURI, user)
				defer os.RemoveAll(path)
				if err != nil {
					return err
				}
				return s.git.ScanRepo(ctx, repo, path, NewScanOptions(), chunksChan)
			}(repoURI)
			if err != nil {
				ctx.Logger().Info("error scanning repository", "repo", repoURI, "error", err)
				continue
			}
		}
	case *sourcespb.Git_Unauthenticated:
		for i, repoURI := range s.conn.Repositories {
			s.SetProgressComplete(i, totalRepos, fmt.Sprintf("Repo: %s", repoURI), "")
			if len(repoURI) == 0 {
				continue
			}
			err := func(repoURI string) error {
				path, repo, err := CloneRepoUsingUnauthenticated(ctx, repoURI)
				defer os.RemoveAll(path)
				if err != nil {
					return err
				}
				return s.git.ScanRepo(ctx, repo, path, NewScanOptions(), chunksChan)
			}(repoURI)
			if err != nil {
				ctx.Logger().Info("error scanning repository", "repo", repoURI, "error", err)
				continue
			}
		}
	case *sourcespb.Git_SshAuth:
		for i, repoURI := range s.conn.Repositories {
			s.SetProgressComplete(i, totalRepos, fmt.Sprintf("Repo: %s", repoURI), "")
			if len(repoURI) == 0 {
				continue
			}
			err := func(repoURI string) error {
				path, repo, err := CloneRepoUsingSSH(ctx, repoURI)
				defer os.RemoveAll(path)
				if err != nil {
					return err
				}
				return s.git.ScanRepo(ctx, repo, path, NewScanOptions(), chunksChan)
			}(repoURI)
			if err != nil {
				ctx.Logger().Info("error scanning repository", "repo", repoURI, "error", err)
				continue
			}
		}
	default:
		return errors.New("invalid connection type for git source")
	}

	for i, gitDir := range s.conn.Directories {
		s.SetProgressComplete(len(s.conn.Repositories)+i, totalRepos, fmt.Sprintf("Repo: %s", gitDir), "")

		if len(gitDir) == 0 {
			continue
		}
		if !strings.HasSuffix(gitDir, "git") {
			// try paths instead of url
			repo, err := RepoFromPath(gitDir)
			if err != nil {
				ctx.Logger().Info("error scanning repository", "repo", gitDir, "error", err)
				continue
			}

			err = func(repoPath string) error {
				if strings.HasPrefix(repoPath, filepath.Join(os.TempDir(), "trufflehog")) {
					defer os.RemoveAll(repoPath)
				}

				return s.git.ScanRepo(ctx, repo, repoPath, NewScanOptions(), chunksChan)
			}(gitDir)
			if err != nil {
				ctx.Logger().Info("error scanning repository", "repo", gitDir, "error", err)
				continue
			}
		}

	}

	ctx.Logger().V(1).Info("Git source finished scanning", "repo-count", totalRepos)
	s.SetProgressComplete(
		totalRepos, totalRepos,
		fmt.Sprintf("Completed scanning source %s", s.name), "",
	)
	return nil
}

func RepoFromPath(path string) (*git.Repository, error) {
	return git.PlainOpen(path)
}

func CleanOnError(err *error, path string) {
	if *err != nil {
		os.RemoveAll(path)
	}
}

func gitURLParse(gitURL string) (*url.URL, error) {
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

func CloneRepo(ctx context.Context, userInfo *url.Userinfo, gitUrl string, args ...string) (string, *git.Repository, error) {
	if err := gitCmdCheck(); err != nil {
		return "", nil, err
	}
	clonePath, err := ioutil.TempDir(os.TempDir(), "trufflehog")
	if err != nil {
		return "", nil, err
	}
	defer CleanOnError(&err, clonePath)
	cloneURL, err := gitURLParse(gitUrl)
	if err != nil {
		return "", nil, err
	}
	if cloneURL.User == nil {
		cloneURL.User = userInfo
	}

	gitArgs := []string{"clone", cloneURL.String(), clonePath}
	gitArgs = append(gitArgs, args...)
	cloneCmd := exec.Command("git", gitArgs...)

	safeUrl, err := stripPassword(gitUrl)
	if err != nil {
		ctx.Logger().V(1).Info("error stripping password from git url", "error", err)
	}
	logger := ctx.Logger().WithValues(
		"subcommand", "git clone",
		"repo", safeUrl,
		"path", clonePath,
		"args", args,
	)

	// Execute command and wait for the stdout / stderr.
	output, err := cloneCmd.CombinedOutput()
	if err != nil {
		err = errors.WrapPrefix(err, "error running 'git clone'", 0)
	}
	logger.V(3).Info("git subcommand finished", "output", string(output))

	if cloneCmd.ProcessState == nil {
		return "", nil, errors.New("clone command exited with no output")
	}
	if cloneCmd.ProcessState != nil && cloneCmd.ProcessState.ExitCode() != 0 {
		logger.V(1).Info("git clone failed", "error", err)
		return "", nil, fmt.Errorf("could not clone repo: %s, %w", safeUrl, err)
	}

	repo, err := git.PlainOpen(clonePath)
	if err != nil {
		return "", nil, fmt.Errorf("could not open cloned repo: %w", err)
	}

	logger.V(1).Info("successfully cloned repo")
	return clonePath, repo, nil
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
func CloneRepoUsingSSH(ctx context.Context, gitUrl string, args ...string) (string, *git.Repository, error) {
	userInfo := url.User("git")
	return CloneRepo(ctx, userInfo, gitUrl, args...)
}

// gitCmdCheck checks if git is installed.
func gitCmdCheck() error {
	if errors.Is(exec.Command("git").Run(), exec.ErrNotFound) {
		return fmt.Errorf("'git' command not found in $PATH. Make sure git is installed and included in $PATH")
	}
	return nil
}

func (s *Git) ScanCommits(ctx context.Context, repo *git.Repository, path string, scanOptions *ScanOptions, chunksChan chan *sources.Chunk) error {
	if err := gitCmdCheck(); err != nil {
		return err
	}

	commitChan, err := gitparse.NewParser().RepoPath(ctx, path, scanOptions.HeadHash, scanOptions.BaseHash == "")
	if err != nil {
		return err
	}
	if commitChan == nil {
		return nil
	}

	// get the URL metadata for reporting (may be empty)
	urlMetadata := getSafeRemoteURL(repo, "origin")

	var depth int64

	logger := ctx.Logger().WithValues("repo", urlMetadata)
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
			when = commit.Date.String()

			// Handle binary files by reading the entire file rather than using the diff.
			if diff.IsBinary {
				commitHash := plumbing.NewHash(hash)
				metadata := s.sourceMetadataFunc(fileName, email, hash, when, urlMetadata, 0)
				chunkSkel := &sources.Chunk{
					SourceName:     s.sourceName,
					SourceID:       s.sourceID,
					SourceType:     s.sourceType,
					SourceMetadata: metadata,
					Verify:         s.verify,
				}
				if err := handleBinary(ctx, repo, chunksChan, chunkSkel, commitHash, fileName); err != nil {
					logger.V(1).Info("error handling binary file", "error", err, "filename", fileName, "commit", commitHash, "file", diff.PathB)
				}
				continue
			}

			if diff.Content.Len() > sources.ChunkSize+sources.PeekSize {
				s.gitChunk(ctx, diff, fileName, email, hash, when, urlMetadata, chunksChan)
				continue
			}
			metadata := s.sourceMetadataFunc(fileName, email, hash, when, urlMetadata, int64(diff.LineStart))
			chunksChan <- &sources.Chunk{
				SourceName:     s.sourceName,
				SourceID:       s.sourceID,
				SourceType:     s.sourceType,
				SourceMetadata: metadata,
				Data:           diff.Content.Bytes(),
				Verify:         s.verify,
			}
		}
	}
	return nil
}

func (s *Git) gitChunk(ctx context.Context, diff gitparse.Diff, fileName, email, hash, when, urlMetadata string, chunksChan chan *sources.Chunk) {
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
				chunksChan <- &sources.Chunk{
					SourceName:     s.sourceName,
					SourceID:       s.sourceID,
					SourceType:     s.sourceType,
					SourceMetadata: metadata,
					Data:           append([]byte{}, newChunkBuffer.Bytes()...),
					Verify:         s.verify,
				}
				newChunkBuffer.Reset()
				lastOffset = offset
			}
			if len(line) > sources.ChunkSize {
				// Send the oversize line.
				metadata := s.sourceMetadataFunc(fileName, email, hash, when, urlMetadata, int64(diff.LineStart+offset))
				chunksChan <- &sources.Chunk{
					SourceName:     s.sourceName,
					SourceID:       s.sourceID,
					SourceType:     s.sourceType,
					SourceMetadata: metadata,
					Data:           line,
					Verify:         s.verify,
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
		chunksChan <- &sources.Chunk{
			SourceName:     s.sourceName,
			SourceID:       s.sourceID,
			SourceType:     s.sourceType,
			SourceMetadata: metadata,
			Data:           append([]byte{}, newChunkBuffer.Bytes()...),
			Verify:         s.verify,
		}
	}
}

// ScanUnstaged chunks unstaged changes.
func (s *Git) ScanUnstaged(ctx context.Context, repo *git.Repository, path string, scanOptions *ScanOptions, chunksChan chan *sources.Chunk) error {
	// get the URL metadata for reporting (may be empty)
	urlMetadata := getSafeRemoteURL(repo, "origin")

	commitChan, err := gitparse.NewParser().Unstaged(ctx, path)
	if err != nil {
		return err
	}
	if commitChan == nil {
		return nil
	}

	var depth int64
	var reachedBase = false

	ctx.Logger().V(1).Info("scanning unstaged changes", "path", path)
	for commit := range commitChan {
		for _, diff := range commit.Diffs {
			logger := ctx.Logger().WithValues("filename", diff.PathB, "commit", commit.Hash, "file", diff.PathB)
			logger.V(2).Info("scanning unstaged changes from git")

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
			when = commit.Date.String()

			// Handle binary files by reading the entire file rather than using the diff.
			if diff.IsBinary {
				commitHash := plumbing.NewHash(hash)
				metadata := s.sourceMetadataFunc(fileName, email, "Unstaged", when, urlMetadata, 0)
				chunkSkel := &sources.Chunk{
					SourceName:     s.sourceName,
					SourceID:       s.sourceID,
					SourceType:     s.sourceType,
					SourceMetadata: metadata,
					Verify:         s.verify,
				}
				if err := handleBinary(ctx, repo, chunksChan, chunkSkel, commitHash, fileName); err != nil {
					logger.V(1).Info("error handling binary file", "error", err, "filename", fileName)
				}
				continue
			}

			metadata := s.sourceMetadataFunc(fileName, email, "Unstaged", when, urlMetadata, int64(diff.LineStart))
			chunksChan <- &sources.Chunk{
				SourceName:     s.sourceName,
				SourceID:       s.sourceID,
				SourceType:     s.sourceType,
				SourceMetadata: metadata,
				Data:           diff.Content.Bytes(),
				Verify:         s.verify,
			}
		}
	}
	return nil
}

func (s *Git) ScanRepo(ctx context.Context, repo *git.Repository, repoPath string, scanOptions *ScanOptions, chunksChan chan *sources.Chunk) error {
	if scanOptions == nil {
		scanOptions = NewScanOptions()
	}
	if err := normalizeConfig(scanOptions, repo); err != nil {
		return err
	}
	start := time.Now().UnixNano()
	if err := s.ScanCommits(ctx, repo, repoPath, scanOptions, chunksChan); err != nil {
		return err
	}
	if err := s.ScanUnstaged(ctx, repo, repoPath, scanOptions, chunksChan); err != nil {
		ctx.Logger().V(1).Info("error scanning unstaged changes", "error", err)
	}

	// We're logging time, but the repoPath is usally a dynamically generated folder in /tmp
	// To make this duration logging useful, we need to log the remote as well
	remotes, _ := repo.Remotes()
	repoUrl := "Could not get remote for repo"
	if len(remotes) != 0 {
		repoUrl = getSafeRemoteURL(repo, remotes[0].Config().Name)
	}

	scanTime := time.Now().UnixNano() - start
	ctx.Logger().V(1).Info("scanning git repo complete", "Repo", repoUrl, "path", repoPath, "time", scanTime)
	return nil
}

func normalizeConfig(scanOptions *ScanOptions, repo *git.Repository) (err error) {
	var baseCommit *object.Commit
	if len(scanOptions.BaseHash) > 0 {
		baseHash := plumbing.NewHash(scanOptions.BaseHash)
		if !plumbing.IsHash(scanOptions.BaseHash) {
			base, err := TryAdditionalBaseRefs(repo, scanOptions.BaseHash)
			if err != nil {
				return errors.WrapPrefix(err, "unable to resolve base ref", 0)
			}
			scanOptions.BaseHash = base.String()
			baseCommit, _ = repo.CommitObject(plumbing.NewHash(scanOptions.BaseHash))
		} else {
			baseCommit, err = repo.CommitObject(baseHash)
			if err != nil {
				return errors.WrapPrefix(err, "unable to resolve base ref", 0)
			}
		}
	}

	var headCommit *object.Commit
	if len(scanOptions.HeadHash) > 0 {
		headHash := plumbing.NewHash(scanOptions.HeadHash)
		if !plumbing.IsHash(scanOptions.HeadHash) {
			head, err := TryAdditionalBaseRefs(repo, scanOptions.HeadHash)
			if err != nil {
				return errors.WrapPrefix(err, "unable to resolve head ref", 0)
			}
			scanOptions.HeadHash = head.String()
			headCommit, _ = repo.CommitObject(plumbing.NewHash(scanOptions.HeadHash))
		} else {
			headCommit, err = repo.CommitObject(headHash)
			if err != nil {
				return errors.WrapPrefix(err, "unable to resolve head ref", 0)
			}
		}
	}

	// If baseCommit is an ancestor of headCommit, update c.BaseRef to be the common ancestor.
	if headCommit != nil && baseCommit != nil {
		mergeBase, err := headCommit.MergeBase(baseCommit)
		if err != nil || len(mergeBase) < 1 {
			return errors.WrapPrefix(err, "could not find common base between the given references", 0)
		}
		scanOptions.BaseHash = mergeBase[0].Hash.String()
	}

	return nil
}

// GenerateLink crafts a link to the specific file from a commit. This works in most major git providers (Github/Gitlab)
func GenerateLink(repo, commit, file string) string {
	// bitbucket links are commits not commit...
	if strings.Contains(repo, "bitbucket.org/") {
		return repo[:len(repo)-4] + "/commits/" + commit
	}
	link := repo[:len(repo)-4] + "/blob/" + commit + "/" + file

	if file == "" {
		link = repo[:len(repo)-4] + "/commit/" + commit
	}
	return link
}

func stripPassword(u string) (string, error) {
	if strings.HasPrefix(u, "git@") {
		return u, nil
	}

	repoURL, err := url.Parse(u)
	if err != nil {
		return "", errors.WrapPrefix(err, "repo remote cannot be sanitized as URI", 0)
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
		if err == plumbing.ErrReferenceNotFound {
			continue
		}
		if err != nil {
			return nil, err
		}
		return outHash, nil
	}

	return nil, fmt.Errorf("no base refs succeeded for base: %q", base)
}

// PrepareRepoSinceCommit clones a repo starting at the given commitHash and returns the cloned repo path.
func PrepareRepoSinceCommit(ctx context.Context, uriString, commitHash string) (string, bool, error) {
	if commitHash == "" {
		return PrepareRepo(ctx, uriString)
	}
	// TODO: refactor with PrepareRepo to remove duplicated logic

	// The git CLI doesn't have an option to shallow clone starting at a commit
	// hash, but it does have an option to shallow clone since a timestamp. If
	// the uriString is github.com, then we query the API for the timestamp of the
	// hash and use that to clone.

	uri, err := gitURLParse(uriString)
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
		tc := oauth2.NewClient(context.TODO(), ts)
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
		ctx.Logger().V(1).Info("cloning repo with authentication", "uri", uri)
		password, ok := uri.User.Password()
		if !ok {
			return "", true, fmt.Errorf("password must be included in Git repo URL when username is provided")
		}
		path, _, err = CloneRepoUsingToken(ctx, password, remotePath, uri.User.Username(), "--shallow-since", timestamp)
		if err != nil {
			return path, true, fmt.Errorf("failed to clone authenticated Git repo (%s): %s", remotePath, err)
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
	uri, err := gitURLParse(uriString)
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
			ctx.Logger().V(1).Info("cloning repo with authentication", "uri", uri)
			password, ok := uri.User.Password()
			if !ok {
				return "", remote, fmt.Errorf("password must be included in Git repo URL when username is provided")
			}
			path, _, err = CloneRepoUsingToken(ctx, password, remotePath, uri.User.Username())
			if err != nil {
				return path, remote, fmt.Errorf("failed to clone authenticated Git repo (%s): %s", remotePath, err)
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

func handleBinary(ctx context.Context, repo *git.Repository, chunksChan chan *sources.Chunk, chunkSkel *sources.Chunk, commitHash plumbing.Hash, path string) error {
	ctx.Logger().V(5).Info("handling binary file", "path", path)
	commit, err := repo.CommitObject(commitHash)
	if err != nil {
		return err
	}

	file, err := commit.File(path)
	if err != nil {
		return err
	}

	fileReader, err := file.Reader()
	if err != nil {
		return err
	}
	defer fileReader.Close()

	reader, err := diskbufferreader.New(fileReader)
	if err != nil {
		return err
	}
	defer reader.Close()

	if handlers.HandleFile(ctx, reader, chunkSkel, chunksChan) {
		return nil
	}

	ctx.Logger().V(1).Info("binary file not handled, chunking raw", "path", path)
	if err := reader.Reset(); err != nil {
		return err
	}
	reader.Stop()

	chunkData, err := io.ReadAll(reader)
	if err != nil {
		return err
	}

	chunk := *chunkSkel
	chunk.Data = chunkData
	chunksChan <- &chunk

	return nil
}
