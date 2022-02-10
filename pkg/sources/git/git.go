package git

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/go-errors/errors"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/format/diff"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/semaphore"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
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
	aCtx     context.Context
	sources.Progress
	conn *sourcespb.Git
}

type Git struct {
	sourceType         sourcespb.SourceType
	sourceName         string
	sourceID           int64
	jobID              int64
	sourceMetadataFunc func(file, email, commit, repository string) *source_metadatapb.MetaData
	verify             bool
	// sem is used to limit concurrency
	sem *semaphore.Weighted
}

func NewGit(sourceType sourcespb.SourceType, jobID, sourceID int64, sourceName string, verify bool, concurrency int,
	sourceMetadataFunc func(file, email, commit, repository string) *source_metadatapb.MetaData,
) *Git {
	return &Git{
		sourceType:         sourceType,
		sourceName:         sourceName,
		sourceID:           sourceID,
		jobID:              jobID,
		sourceMetadataFunc: sourceMetadataFunc,
		verify:             verify,
		sem:                semaphore.NewWeighted(int64(concurrency)),
	}
}

// Ensure the Source satisfies the interface at compile time
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

	s.aCtx = aCtx
	s.name = name
	s.sourceId = sourceId
	s.jobId = jobId
	s.verify = verify

	var conn sourcespb.Git
	err := anypb.UnmarshalTo(connection, &conn, proto.UnmarshalOptions{})
	if err != nil {
		errors.WrapPrefix(err, "error unmarshalling connection", 0)
	}

	s.conn = &conn

	s.git = NewGit(s.Type(), s.jobId, s.sourceId, s.name, s.verify, runtime.NumCPU(),
		func(file, email, commit, repository string) *source_metadatapb.MetaData {
			return &source_metadatapb.MetaData{
				Data: &source_metadatapb.MetaData_Git{
					Git: &source_metadatapb.Git{
						Commit:     sanitizer.UTF8(commit),
						File:       sanitizer.UTF8(file),
						Email:      sanitizer.UTF8(email),
						Repository: sanitizer.UTF8(repository),
					},
				},
			}
		})
	return nil
}

// Chunks emits chunks of bytes over a channel.
func (s *Source) Chunks(ctx context.Context, chunksChan chan *sources.Chunk) error {
	switch cred := s.conn.GetCredential().(type) {
	case *sourcespb.Git_BasicAuth:
		user := cred.BasicAuth.Username
		token := cred.BasicAuth.Password

		for i, repoURI := range s.conn.Repositories {
			s.SetProgressComplete(i, len(s.conn.Repositories), fmt.Sprintf("Repo: %s", repoURI))
			if len(repoURI) == 0 {
				continue
			}
			path, repo, err := CloneRepoUsingToken(token, repoURI, user)
			defer os.RemoveAll(path)
			if err != nil {
				return err
			}
			err = s.git.ScanRepo(ctx, repo, NewScanOptions(), chunksChan)
			if err != nil {
				return err
			}
		}
	case *sourcespb.Git_Unauthenticated:
		for i, repoURI := range s.conn.Repositories {
			s.SetProgressComplete(i, len(s.conn.Repositories), fmt.Sprintf("Repo: %s", repoURI))
			if len(repoURI) == 0 {
				continue
			}
			path, repo, err := CloneRepoUsingUnauthenticated(repoURI)
			defer os.RemoveAll(path)
			if err != nil {
				return err
			}
			err = s.git.ScanRepo(ctx, repo, NewScanOptions(), chunksChan)
			if err != nil {
				return err
			}
		}
	default:
		return errors.New("invalid connection type for git source")
	}

	for i, u := range s.conn.Directories {
		s.SetProgressComplete(i, len(s.conn.Repositories), fmt.Sprintf("Repo: %s", u))

		if len(u) == 0 {
			continue
		}
		if !strings.HasSuffix(u, "git") {
			//try paths instead of url
			repo, err := RepoFromPath(u)
			if err != nil {
				return err
			}
			if strings.HasPrefix(u, filepath.Join(os.TempDir(), "trufflehog")) {
				defer os.RemoveAll(u)
			}

			err = s.git.ScanRepo(ctx, repo, NewScanOptions(), chunksChan)
			if err != nil {
				return err

			}
		}

	}
	return nil
}

func RepoFromPath(path string) (*git.Repository, error) {
	return git.PlainOpen(path)
}

func CloneRepoUsingToken(token, url, user string) (clonePath string, repo *git.Repository, err error) {
	log.Debugf("Scanning Repo: %s", url)
	if user == "" {
		user = "cloner"
	}
	//some git clones require username not just token
	cloneOptions := &git.CloneOptions{
		URL: url,
		Auth: &http.BasicAuth{
			Username: user,
			Password: token,
		},
	}
	clonePath, err = ioutil.TempDir(os.TempDir(), "trufflehog")
	if err != nil {
		err = errors.New(err)
		return
	}
	repo, err = git.PlainClone(clonePath, false, cloneOptions)
	if err != nil {
		err = errors.New(err)
		return
	}
	safeRepo, err := stripPassword(url)
	if err != nil {
		err = errors.New(err)
		return
	}
	if _, ok := err.(*os.PathError); ok {
		log.WithField("repo", safeRepo).WithError(err).Error("error cloning repo")
	}
	if err != nil && strings.Contains(err.Error(), "cannot read hash, pkt-line too short") {
		log.WithField("repo", safeRepo).WithError(err).Error("error cloning repo")
	}
	return
}

func CloneRepoUsingUnauthenticated(url string) (clonePath string, repo *git.Repository, err error) {
	cloneOptions := &git.CloneOptions{
		URL: url,
	}
	clonePath, err = ioutil.TempDir(os.TempDir(), "trufflehog")
	if err != nil {
		return
	}
	repo, err = git.PlainClone(clonePath, false, cloneOptions)
	if err != nil {
		err = errors.New(err)
		return
	}
	safeRepo, err := stripPassword(url)
	if err != nil {
		err = errors.New(err)
		return
	}
	if _, ok := err.(*os.PathError); ok {
		log.WithField("repo", safeRepo).WithError(err).Error("error cloning repo")
	}
	if err != nil && strings.Contains(err.Error(), "cannot read hash, pkt-line too short") {
		log.WithField("repo", safeRepo).WithError(err).Error("error cloning repo")
	}
	return
}

func (s *Git) ScanCommits(repo *git.Repository, scanOptions *ScanOptions, chunksChan chan *sources.Chunk) error {
	blobsSeen := map[string]bool{}
	commits := map[int64][]*object.Commit{}

	logIter, err := repo.Log(scanOptions.LogOptions)
	if err != nil {
		log.Fatal(err)
	}

	keys := []int64{}

	sinceTime := int64(0)

	logIter.ForEach(func(commit *object.Commit) error {
		key := commit.Committer.When.Unix()
		if scanOptions.SinceCommit != nil && scanOptions.SinceCommit.Hash.String() == commit.Hash.String() {
			sinceTime = key
		}
		if existing, ok := commits[key]; ok {
			commits[key] = append(existing, commit)
		} else {
			commits[key] = []*object.Commit{commit}
			keys = append(keys, key)
		}
		return nil
	})

	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })

	remote, err := repo.Remote("origin")
	if err != nil {
		return errors.New(err)
	}
	safeRepo, err := stripPassword(remote.Config().URLs[0])
	if err != nil {
		return errors.New(err)
	}

	start := int64(0)
	if scanOptions.MaxDepth > 0 && scanOptions.MaxDepth < int64(len(keys)) {
		start = int64(len(keys)) - scanOptions.MaxDepth
	}

	scannedCommits := []string{}
	for _, key := range keys[start:] {
		if sinceTime > key {
			continue
		}
		for _, commit := range commits[key] {
			scannedCommits = append(scannedCommits, commit.Hash.String())
			fileIter, err := commit.Files()
			if err != nil {
				return err
			}
			err = fileIter.ForEach(func(file *object.File) error {
				if _, scanned := blobsSeen[file.Hash.String()]; scanned || !scanOptions.Filter.Pass(file.Name) {
					return nil
				}
				blobsSeen[file.Hash.String()] = true
				metadata := s.sourceMetadataFunc(file.Name, commit.Author.Email, commit.Hash.String(), safeRepo)
				reader, err := file.Reader()
				if err != nil {
					return nil
				}
				defer reader.Close()
				buffer := new(bytes.Buffer)
				buffer.ReadFrom(reader)
				chunksChan <- &sources.Chunk{
					SourceType:     s.sourceType,
					SourceName:     s.sourceName,
					SourceID:       s.sourceID,
					Data:           buffer.Bytes(),
					SourceMetadata: metadata,
					Verify:         s.verify,
				}
				return nil
			})
			if err != nil {
				return err
			}
		}
	}
	if err != nil && !strings.Contains(err.Error(), "max_depth exceeded") && !strings.Contains(err.Error(), "reached since_commit") {
		return err
	}
	return nil
}

func (s *Git) ScanUnstaged(repo *git.Repository, scanOptions *ScanOptions, chunksChan chan *sources.Chunk) error {
	remote, err := repo.Remote("origin")
	if err != nil {
		return errors.New(err)
	}
	safeRepo, err := stripPassword(remote.Config().URLs[0])
	if err != nil {
		return errors.New(err)
	}

	// Also scan any unstaged changes in the working tree of the repo
	_, err = repo.Head()
	if err == nil || err == plumbing.ErrReferenceNotFound {
		wt, err := repo.Worktree()
		if err != nil {
			log.WithError(err).Error("error obtaining repo worktree")
			return err
		}

		status, err := wt.Status()
		if err != nil {
			log.WithError(err).Error("error obtaining worktree status")
			return err
		}
		for fh := range status {
			if !scanOptions.Filter.Pass(fh) {
				continue
			}
			metadata := s.sourceMetadataFunc(
				fh, "unstaged", "unstaged", safeRepo,
			)

			fileBuf := bytes.NewBuffer(nil)
			fileHandle, err := wt.Filesystem.Open(fh)
			if err != nil {
				continue
			}
			defer fileHandle.Close()
			_, err = io.Copy(fileBuf, fileHandle)
			if err != nil {
				continue
			}
			chunksChan <- &sources.Chunk{
				SourceType:     s.sourceType,
				SourceName:     s.sourceName,
				SourceID:       s.sourceID,
				Data:           fileBuf.Bytes(),
				SourceMetadata: metadata,
				Verify:         s.verify,
			}
		}
	}
	return nil
}

func (s *Git) ScanRepo(ctx context.Context, repo *git.Repository, scanOptions *ScanOptions, chunksChan chan *sources.Chunk) error {
	if err := s.ScanCommits(repo, scanOptions, chunksChan); err != nil {
		return err
	}
	if err := s.ScanUnstaged(repo, scanOptions, chunksChan); err != nil {
		// https://github.com/src-d/go-git/issues/879
		if strings.Contains(err.Error(), "object not found") {
			log.WithError(err).Error("known issue: probably caused by a dangling reference in the repo")
		} else {
			return errors.New(err)
		}
		return err
	}
	return nil
}

//GenerateLink crafts a link to the specific file from a commit. This works in most major git providers (Github/Gitlab)
func GenerateLink(repo, commit, file string) string {
	//bitbucket links are commits not commit...
	if strings.Contains(repo, "bitbucket.org/") {
		return repo[:len(repo)-4] + "/commits/" + commit
	}
	link := repo[:len(repo)-4] + "/blob/" + commit + "/" + file

	if file == "" {
		link = repo[:len(repo)-4] + "/commit/" + commit
	}
	return link
}

func (s *Git) scanCommitPatches(ctx context.Context, repo *git.Repository, commit *object.Commit, chunksChan chan *sources.Chunk, filter *common.Filter) error {

	defer func() {
		if err := recover(); err != nil {
			return
		}
	}()

	// If there are no parents, just scan all files present in the commit
	//log.Debugf("scanning: %v : %s", repo, commit.Hash)
	if len(commit.ParentHashes) == 0 {
		err := s.scanFilesForCommit(ctx, repo, commit, chunksChan)
		if err != nil {
			return errors.New(err)
		}
		return nil
	}

	parent, err := commit.Parent(0)
	if err != nil {
		return errors.New(err)
	}

	remote, err := repo.Remote("origin")
	if err != nil {
		return errors.New(err)
	}

	safeRepo, err := stripPassword(remote.Config().URLs[0])
	if err != nil {
		return errors.New(err)
	}

	patchCtx, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()
	patch, err := parent.PatchContext(patchCtx, commit)
	if err != nil {
		if errors.Is(context.DeadlineExceeded, err) {
			return nil
		}
		return errors.New(err)
	}

	email := commit.Author.Email
	commitHash := commit.Hash.String()

	for _, file := range patch.FilePatches() {
		bf, f := file.Files()
		filename := f.Path()
		if !filter.Pass(filename) {
			continue
		}
		if filename == "" {
			filename = bf.Path()
		}

		metadata := s.sourceMetadataFunc(
			filename, email, commitHash, safeRepo,
		)

		chunk := bytes.NewBuffer(nil)
		// This makes a chunk for every section of the diff, so lots of little changes in a file can produce a lot of chunks.
		for _, patchChunk := range file.Chunks() {
			if patchChunk.Type() != diff.Add {
				continue
			}
			// I wonder if we can eliminate this string conversion
			chunk.Write([]byte(patchChunk.Content()))
		}

		chunksChan <- &sources.Chunk{
			SourceType:     s.sourceType,
			SourceName:     s.sourceName,
			SourceID:       s.sourceID,
			Data:           chunk.Bytes(),
			SourceMetadata: metadata,
			Verify:         s.verify,
		}
	}

	return nil
}

func (s *Git) scanFilesForCommit(ctx context.Context, repo *git.Repository, commit *object.Commit, chunksChan chan *sources.Chunk) error {
	fileIter, err := commit.Files()
	if err != nil {
		return errors.New(err)
	}

	remote, err := repo.Remote("origin")
	if err != nil {
		return errors.New(err)
	}
	safeRepo, err := stripPassword(remote.Config().URLs[0])
	if err != nil {
		return errors.New(err)
	}

	err = fileIter.ForEach(func(f *object.File) error {
		isBinary, err := f.IsBinary()
		if isBinary {
			return nil
		}
		if err != nil {
			return errors.New(err)
		}

		chunkStr, err := f.Contents()
		if err != nil {
			return errors.New(err)
		}

		chunksChan <- &sources.Chunk{
			SourceType: s.sourceType,
			SourceName: s.sourceName,
			SourceID:   s.sourceID,
			Data:       []byte(chunkStr),
			SourceMetadata: s.sourceMetadataFunc(
				f.Name, commit.Author.Email, commit.Hash.String(), safeRepo,
			),
			Verify: s.verify,
		}
		return nil
	})

	return err
}

func stripPassword(u string) (string, error) {
	if strings.HasPrefix(u, "git@") {
		return u, nil
	}

	repoURL, err := url.Parse(u)
	if err != nil {
		return "", errors.WrapPrefix(err, "repo remote cannot be sanitized as URI", 0)
	}

	_, passSet := repoURL.User.Password()
	if passSet {
		return strings.Replace(repoURL.String(), repoURL.User.String()+"@", repoURL.User.Username()+":***@", 1), nil
	}
	return repoURL.String(), nil
}

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
func PrepareRepo(uriString string) (string, bool, error) {
	var path string
	uri, err := url.Parse(uriString)
	if err != nil {
		return "", false, fmt.Errorf("unable to parse Git URI: %s", err)
	}

	remote := false
	switch uri.Scheme {
	case "file":
		path = fmt.Sprintf("%s%s", uri.Host, uri.Path)
	case "https":
		remotePath := fmt.Sprintf("%s://%s%s", uri.Scheme, uri.Host, uri.Path)
		remote = true
		switch {
		case uri.User != nil:
			log.Debugf("Cloning remote Git repo with authentication")
			password, ok := uri.User.Password()
			if !ok {
				return "", remote, fmt.Errorf("password must be included in Git repo URL when username is provided")
			}
			path, _, err = CloneRepoUsingToken(password, remotePath, uri.User.Username())
			if err != nil {
				return path, remote, fmt.Errorf("failed to clone authenticated Git repo (%s): %s", remotePath, err)
			}
		default:
			log.Debugf("Cloning remote Git repo without authentication")
			path, _, err = CloneRepoUsingUnauthenticated(remotePath)
			if err != nil {
				return path, remote, fmt.Errorf("failed to clone unauthenticated Git repo (%s): %s", remotePath, err)
			}
		}
	default:
		return "", remote, fmt.Errorf("unsupported Git URI: %s", uriString)
	}
	log.Debugf("Git repo local path: %s", path)
	return path, remote, nil
}

func FilterCommitByFiles(commit *object.Commit, filter *common.Filter) bool {
	fileCount := 0
	fileIter, err := commit.Files()
	if err != nil {
		return true
	}
	foundErr := errors.New("file found")
	err = fileIter.ForEach(func(file *object.File) error {
		fileCount++
		if filter.Pass(file.Name) {
			return foundErr
		}
		return nil
	})
	// fileIter will return a "file found" "error" if any files match the filter. If there are no files, there will
	// not be a match, but the commit should pass anyway in case we want to do something with the commit message.
	if !errors.Is(err, foundErr) && fileCount > 0 {
		return true
	}
	return false
}
