package git

import (
	"bytes"
	"context"
	"fmt"
	"github.com/trufflesecurity/trufflehog/pkg/common"
	"io"
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/go-errors/errors"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/format/diff"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/storer"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/semaphore"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/pkg/pb/sourcespb"

	"github.com/trufflesecurity/trufflehog/pkg/sanitizer"
	"github.com/trufflesecurity/trufflehog/pkg/sources"
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
		return
	}
	repo, err = git.PlainClone(clonePath, false, cloneOptions)
	if err != nil {
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

func (s *Git) ScanRepo(ctx context.Context, repo *git.Repository, scanOptions *ScanOptions, chunksChan chan *sources.Chunk) error {
	wg := &sync.WaitGroup{}

	remote, err := repo.Remote("origin")
	if err != nil {
		return errors.New(err)
	}
	safeRepo, err := stripPassword(remote.Config().URLs[0])
	if err != nil {
		return errors.New(err)
	}

	commitIter, err := repo.Log(scanOptions.LogOptions)
	if err != nil {
		return errors.New(err)
	}

	scanOneCommit := false
	if scanOptions.SinceCommit != nil && scanOptions.LogOptions.From.String() == scanOptions.SinceCommit.Hash.String() {
		// Our head and base commits are the same, so scan the one commit
		scanOneCommit = true
	}
	breakIteration := false

	depth := int64(0)
	err = commitIter.ForEach(func(commit *object.Commit) error {
		if breakIteration {
			return storer.ErrStop
		}
		if scanOneCommit {
			breakIteration = true
		}

		// TODO: Clean up this conditional mess.
		if (scanOptions.SinceCommit != nil && commit.Hash == scanOptions.SinceCommit.Hash && !scanOneCommit) ||
			(scanOptions.MaxDepth >= 0 && depth >= scanOptions.MaxDepth) {
			return storer.ErrStop
		}
		depth++

		err = s.scanCommitPatches(ctx, repo, commit, chunksChan, scanOptions.Filter)
		if err != nil {
			switch e := err.Error(); {
			case strings.Contains(e, "operation canceled"):
				log.WithError(err).
					WithField("repo", safeRepo).
					WithField("commit", commit.Hash.String()).
					Warn("commit took too long to compute")
				return nil
			case strings.Contains(e, "packfile not found"):
				log.WithError(err).WithField("repo", safeRepo).Warn("invalid commit reference while scanning commit")
				return nil
			default:
				log.WithError(err).WithField("repo", safeRepo).Error("unhandled error scanning commit")
				return err
			}
		}
		return nil
	})
	if err != nil {
		// https://github.com/src-d/go-git/issues/879
		if strings.Contains(err.Error(), "object not found") {
			log.WithError(err).Error("known issue: probably caused by a dangling reference in the repo")
		} else {
			return errors.New(err)
		}
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

	wg.Wait()
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
