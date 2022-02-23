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
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sanitizer"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"golang.org/x/sync/semaphore"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
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
	commitIter, err := repo.Log(scanOptions.LogOptions)
	if err != nil {
		return err
	}
	commits := map[int64][]*object.Commit{}

	depth := int64(0)

	if scanOptions.BaseCommit != nil {
		parentHashes := scanOptions.BaseCommit.ParentHashes
		for _, parentHash := range parentHashes {
			parentCommit, err := repo.CommitObject(parentHash)
			if err != nil {
				log.WithError(err).WithField("parentHash", parentHash.String()).WithField("commit", scanOptions.BaseCommit.Hash.String()).Debug("could not find parent commit")
			}
			dummyMap := map[plumbing.Hash]bool{}
			s.scanCommit(repo, parentCommit, &dummyMap, scanOptions, true, chunksChan)
		}
	}

	// Create a map of timestamps to commits.
	commitIter.ForEach(func(commit *object.Commit) error {
		if scanOptions.BaseCommit != nil && commit.Hash.String() == scanOptions.BaseCommit.Hash.String() {
			return errors.New("reached base commit")
		}
		time := commit.Committer.When.Unix()
		if _, ok := commits[time]; !ok {
			commits[time] = []*object.Commit{}
		}
		commits[time] = append(commits[time], commit)
		depth++
		if scanOptions.MaxDepth > int64(0) && depth >= scanOptions.MaxDepth {
			return errors.New("reached max depth")
		}
		return nil
	})

	// Make a slice of all the timestamp keys so it can be sorted.
	keys := make([]int64, len(commits))
	i := 0
	for key, _ := range commits {
		keys[i] = key
		i++
	}

	seenMap := map[plumbing.Hash]bool{}

	// Sort the timestamps
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	for _, commitTime := range keys {
		commitSlice := commits[commitTime]
		for _, commit := range commitSlice {
			// Check to make sure a commit's parents are scanned before the commit. This is done by checking each
			// commit's timestamp to the later of it's two parents.
			laterParent := int64(0)
			for _, parentHash := range commit.ParentHashes {
				parent, err := repo.CommitObject(parentHash)
				if err != nil {
					continue
				}
				parentTime := parent.Committer.When.Unix()
				if commitTime > parentTime {
					continue
				}
				log.WithField("parentTime", parentTime).WithField("commitTime", commitTime).Debugf("commit %s is out of order", commit.Hash)
				if parentTime > laterParent {
					laterParent = parentTime
				}
			}
			// If the commit has an earlier timestamp than it's parents, something has gone wrong. Moving the commit
			// to the end of the timestamp the parent is in will ensure the parents are scanned first.
			if laterParent > 0 {
				log.Debugf("commit (%s) is out of order moving after its parent", commit.Hash)
				commits[laterParent] = append(commits[laterParent], commit)
			}

			s.scanCommit(repo, commit, &seenMap, scanOptions, false, chunksChan)
		}
	}
	return nil
}

func (s *Git) scanCommit(repo *git.Repository, commit *object.Commit, seenMap *map[plumbing.Hash]bool, scanOptions *ScanOptions, ignoreResult bool, chunksChan chan *sources.Chunk) {
	remote, err := repo.Remote("origin")
	if err != nil {
		log.Errorf("error getting repo name: %s", err)
		return
	}
	safeRepo, err := stripPassword(remote.Config().URLs[0])
	if err != nil {
		log.WithError(err).Errorf("couldn't get repo name")
		return
	}
	fileIter, err := commit.Files()
	if err != nil {
		log.WithError(err).WithField("commit", commit.Hash.String()).Errorf("unable to read files")
		return
	}
	fileIter.ForEach(func(file *object.File) error {
		if _, ok := (*seenMap)[file.Hash]; ok {
			return nil
		}

		if !scanOptions.Filter.Pass(file.Name) {
			return nil
		}

		reader, err := file.Reader()
		if err != nil {
			log.WithError(err).WithField("file", file.Name).Debugf("failed to get reader from file")
			return nil
		}
		defer reader.Close()
		bytes, err := ioutil.ReadAll(reader)
		if err != nil {
			log.WithError(err).WithField("file", file.Name).Debugf("failed to read from file")
			return nil
		}

		metadata := s.sourceMetadataFunc(file.Name, commit.Committer.Email, commit.Hash.String(), safeRepo)
		chunksChan <- &sources.Chunk{
			SourceName:     s.sourceName,
			SourceID:       s.sourceID,
			SourceType:     s.sourceType,
			SourceMetadata: metadata,
			Data:           bytes,
			Verify:         s.verify,
			IgnoreResult:   ignoreResult,
		}
		(*seenMap)[file.Hash] = true
		return nil
	})
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
	if err := verifyOptions(scanOptions); err != nil {
		return err
	}

	start := time.Now().UnixNano()
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
	scanTime := time.Now().UnixNano() - start
	log.Debugf("Scanning complete. Scan time: %f", time.Duration(scanTime).Seconds())
	return nil
}

func verifyOptions(scanOptions *ScanOptions) error {
	base := scanOptions.BaseCommit
	head := scanOptions.HeadCommit
	if base != nil && head != nil {
		if ok, _ := base.IsAncestor(head); !ok {
			return fmt.Errorf("unable to scan from requested head to end commit. %s is not an ancestor of %s", base, head)
		}
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
