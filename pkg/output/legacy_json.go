package output

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"
	"sync"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/sergi/go-diff/diffmatchpatch"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/git"
)

// LegacyJSONPrinter is a printer that prints results in legacy JSON format for backwards compatibility.
type LegacyJSONPrinter struct{ mu sync.Mutex }

func (p *LegacyJSONPrinter) Print(ctx context.Context, r *detectors.ResultWithMetadata) error {
	var repo string
	switch r.SourceType {
	case sourcespb.SourceType_SOURCE_TYPE_GIT:
		repo = r.SourceMetadata.GetGit().Repository
	case sourcespb.SourceType_SOURCE_TYPE_GITHUB:
		repo = r.SourceMetadata.GetGithub().Repository
	case sourcespb.SourceType_SOURCE_TYPE_GITLAB:
		repo = r.SourceMetadata.GetGitlab().Repository
	default:
		return fmt.Errorf("unsupported source type for legacy json output: %s", r.SourceType)
	}

	// cloning the repo again here is not great and only works with unauthed repos
	repoPath, remote, err := git.PrepareRepo(ctx, repo)
	if err != nil || repoPath == "" {
		return fmt.Errorf("error preparing git repo for scanning: %w", err)
	}
	if remote {
		defer os.RemoveAll(repoPath)
	}

	legacy, err := convertToLegacyJSON(r, repoPath)
	if err != nil {
		return fmt.Errorf("could not convert to legacy JSON: %w", err)
	}
	out, err := json.Marshal(legacy)
	if err != nil {
		return fmt.Errorf("could not marshal result: %w", err)
	}

	p.mu.Lock()
	fmt.Println(string(out))
	p.mu.Unlock()
	return nil
}

func convertToLegacyJSON(r *detectors.ResultWithMetadata, repoPath string) (*LegacyJSONOutput, error) {
	var source LegacyJSONCompatibleSource
	switch r.SourceType {
	case sourcespb.SourceType_SOURCE_TYPE_GIT:
		source = r.SourceMetadata.GetGit()
	case sourcespb.SourceType_SOURCE_TYPE_GITHUB:
		source = r.SourceMetadata.GetGithub()
	case sourcespb.SourceType_SOURCE_TYPE_GITLAB:
		source = r.SourceMetadata.GetGitlab()
	default:
		return nil, fmt.Errorf("legacy JSON output can not be used with this source: %s", r.SourceName)
	}

	options := &gogit.PlainOpenOptions{
		DetectDotGit:          true,
		EnableDotGitCommonDir: true,
	}

	// The repo will be needed to gather info needed for the legacy output that
	// isn't included in the new output format.
	repo, err := gogit.PlainOpenWithOptions(repoPath, options)
	if err != nil {
		return nil, fmt.Errorf("could not open repo %q: %w", repoPath, err)
	}

	fileName := source.GetFile()
	commitHash := plumbing.NewHash(source.GetCommit())
	commit, err := repo.CommitObject(commitHash)
	if err != nil {
		log.Fatal(err)
	}

	diff := GenerateDiff(commit, fileName)

	foundString := string(r.Result.Raw)

	// Add highlighting to the offending bit of string.
	printableDiff := strings.ReplaceAll(diff, foundString, fmt.Sprintf("\u001b[93m%s\u001b[0m", foundString))

	// Load up the struct to match the old JSON format
	output := &LegacyJSONOutput{
		Branch:       FindBranch(commit, repo),
		Commit:       commit.Message,
		CommitHash:   commitHash.String(),
		Date:         commit.Committer.When.Format("2006-01-02 15:04:05"),
		Diff:         diff,
		Path:         fileName,
		PrintDiff:    printableDiff,
		Reason:       r.Result.DetectorType.String(),
		StringsFound: []string{foundString},
	}
	return output, nil
}

// BranchHeads creates a map of branch names to their head commit. This can be used to find if a commit is an ancestor
// of a branch head.
func BranchHeads(repo *gogit.Repository) (map[string]*object.Commit, error) {
	branches := map[string]*object.Commit{}
	branchIter, err := repo.Branches()
	if err != nil {
		return branches, err
	}

	logger := context.Background().Logger()
	err = branchIter.ForEach(func(branchRef *plumbing.Reference) error {
		branchName := branchRef.Name().String()
		headHash, err := repo.ResolveRevision(plumbing.Revision(branchName))
		if err != nil {
			logger.Error(err, "unable to resolve head of branch", "branch", branchRef.Name().String())
			return nil
		}
		headCommit, err := repo.CommitObject(*headHash)
		if err != nil {
			logger.Error(err, "unable to get commit", "head_hash", headHash.String())
			return nil
		}
		branches[branchName] = headCommit
		return nil
	})
	return branches, err
}

// FindBranch returns the first branch a commit is a part of. Not the most accurate, but it should work similar to pre v3.0.
func FindBranch(commit *object.Commit, repo *gogit.Repository) string {
	logger := context.Background().Logger()
	branches, err := BranchHeads(repo)
	if err != nil {
		logger.Error(err, "could not list branches")
		os.Exit(1)
	}

	for name, head := range branches {
		isAncestor, err := commit.IsAncestor(head)
		if err != nil {
			logger.Error(err, fmt.Sprintf("could not determine if %s is an ancestor of %s", commit.Hash.String(), head.Hash.String()))
			continue
		}
		if isAncestor {
			return name
		}
	}
	return ""
}

// GenerateDiff will take a commit and create a string diff between the commit and its first parent.
func GenerateDiff(commit *object.Commit, fileName string) string {
	var diff string
	logger := context.Background().Logger().WithValues("file", fileName)

	// First grab the first parent of the commit. If there are none, we are at the first commit and should diff against
	// an empty file.
	parent, err := commit.Parent(0)
	if !errors.Is(err, object.ErrParentNotFound) && err != nil {
		logger.Error(err, "could not find parent", "commit", commit.Hash.String())
	}

	// Now get the files from the commit and its parent.
	var parentFile *object.File
	if parent != nil {
		parentFile, err = parent.File(fileName)
		if err != nil && !errors.Is(err, object.ErrFileNotFound) {
			logger.Error(err, "could not get previous version of file")
			return diff
		}
	}
	commitFile, err := commit.File(fileName)
	if err != nil {
		logger.Error(err, "could not get current version of file")
		return diff
	}

	// go-git doesn't support creating a diff for just one file in a commit, so another package is needed to generate
	// the diff.
	dmp := diffmatchpatch.New()
	var oldContent, newContent string
	if parentFile != nil {
		oldContent, err = parentFile.Contents()
		if err != nil {
			logger.Error(err, "could not get contents of previous version of file")
		}
	}
	// commitFile should never be nil at this point, but double-checking so we don't get a nil error.
	if commitFile != nil {
		newContent, _ = commitFile.Contents()
		if err != nil {
			logger.Error(err, "could not get contents of current version of file")
		}
	}

	// If anything has gone wrong here, we'll just be diffing two empty files.
	diffs := dmp.DiffMain(oldContent, newContent, false)
	patches := dmp.PatchMake(diffs)

	// Put all the pieces of the diff together into one string.
	for _, patch := range patches {
		// The String() method URL escapes the diff, so it needs to be undone.
		patchDiff, err := url.QueryUnescape(patch.String())
		if err != nil {
			logger.Error(err, "unable to unescape diff")
		}
		diff += patchDiff
	}
	return diff
}

type LegacyJSONOutput struct {
	Branch       string   `json:"branch"`
	Commit       string   `json:"commit"`
	CommitHash   string   `json:"commitHash"`
	Date         string   `json:"date"`
	Diff         string   `json:"diff"`
	Path         string   `json:"path"`
	PrintDiff    string   `json:"printDiff"`
	Reason       string   `json:"reason"`
	StringsFound []string `json:"stringsFound"`
}

type LegacyJSONCompatibleSource interface {
	GetCommit() string
	GetFile() string
}
