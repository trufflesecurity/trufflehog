package gitparse

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-logr/logr"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	bufferwriter "github.com/trufflesecurity/trufflehog/v3/pkg/writers/buffer_writer"
	bufferedfilewriter "github.com/trufflesecurity/trufflehog/v3/pkg/writers/buffered_file_writer"
)

const (
	// defaultDateFormat is the standard date format for git.
	// Uses ISO 8601 format to avoid locale-dependent weekday/month names.
	defaultDateFormat = time.RFC3339

	// defaultMaxDiffSize is the maximum size for a diff. Larger diffs will be cut off.
	defaultMaxDiffSize int64 = 2 * 1024 * 1024 * 1024 // 2GB

	// defaultMaxCommitSize is the maximum size for a commit. Larger commits will be cut off.
	defaultMaxCommitSize int64 = 2 * 1024 * 1024 * 1024 // 2GB

	// defaultWaitDelay is the default time to wait after context cancellation before forcefully killing git processes.
	defaultWaitDelay = 5 * time.Second

	// logGroupSize is the number of commits per `git log` in the lower-memory scan mode.
	//
	// The hashes are fed in on stdin rather than as arguments, so a group is not
	// limited by how long a command line may be and we can use full hashes. Bigger
	// groups mean fewer git processes to start; each one still only holds state for
	// its own group, which is what keeps memory flat however long the history is.
	logGroupSize = 5000
)

// contentWriter defines a common interface for writing, reading, and managing diff content.
// It abstracts the underlying storage mechanism, allowing flexibility in how content is handled.
// This interface enables the use of different content storage strategies (e.g., in-memory buffer, file-based storage)
// based on performance needs or resource constraints, providing a unified way to interact with different content types.
type contentWriter interface { // Write appends data to the content storage.
	// Write appends data to the content storage.
	Write(data []byte) (int, error)
	// ReadCloser provides a reader for accessing stored content.
	ReadCloser() (io.ReadCloser, error)
	// CloseForWriting closes the content storage for writing.
	CloseForWriting() error
	// Len returns the current size of the content.
	Len() int
	// String returns the content as a string or an error if the content cannot be converted to a string.
	String() (string, error)
}

// Diff contains the information about a file diff in a commit.
// It abstracts the underlying content representation, allowing for flexible handling of diff content.
// The use of contentWriter enables the management of diff data either in memory or on disk,
// based on its size, optimizing resource usage and performance.
type Diff struct {
	PathB     string
	LineStart int
	IsBinary  bool

	Commit *Commit

	contentWriter contentWriter
}

type diffOption func(*Diff)

// withPathB sets the PathB option.
func withPathB(pathB string) diffOption { return func(d *Diff) { d.PathB = pathB } }

// withCustomContentWriter sets the useCustomContentWriter option.
func withCustomContentWriter(cr contentWriter) diffOption {
	return func(d *Diff) { d.contentWriter = cr }
}

// newDiff creates a new Diff with a threshold and an associated commit.
// All Diffs must have an associated commit.
// The contentWriter is used to manage the diff's content, allowing for flexible handling of diff data.
// By default, a buffer is used as the contentWriter, but this can be overridden with a custom contentWriter.
func newDiff(commit *Commit, opts ...diffOption) *Diff {
	diff := &Diff{Commit: commit}
	for _, opt := range opts {
		opt(diff)
	}

	if diff.contentWriter == nil {
		diff.contentWriter = bufferwriter.New()
	}

	return diff
}

// Len returns the length of the storage.
func (d *Diff) Len() int { return d.contentWriter.Len() }

// ReadCloser returns a ReadCloser for the contentWriter.
func (d *Diff) ReadCloser() (io.ReadCloser, error) { return d.contentWriter.ReadCloser() }

// write delegates to the contentWriter.
func (d *Diff) write(p []byte) error {
	_, err := d.contentWriter.Write(p)
	return err
}

// finalize ensures proper closure of resources associated with the Diff.
// handle the final flush in the finalize method, in case there's data remaining in the buffer.
// This method should be called to release resources, especially when writing to a file.
func (d *Diff) finalize() error { return d.contentWriter.CloseForWriting() }

// Commit contains commit header info and diffs.
type Commit struct {
	Hash      string
	Author    string
	Committer string
	Date      time.Time
	Message   strings.Builder
	Size      int // in bytes

	hasDiffs bool
}

// Parser sets values used in GitParse.
type Parser struct {
	maxDiffSize   int64
	maxCommitSize int64
	dateFormat    string
	waitDelay     time.Duration

	useCustomContentWriter bool
	lowMemoryScan          bool

	// groupSize is how many commits go to each `git log` in the lower-memory scan.
	// Zero means logGroupSize. Only the tests set it, so they can put a group
	// boundary wherever they need one.
	groupSize int
}

type ParseState int

const (
	Initial ParseState = iota
	CommitLine
	MergeLine
	AuthorLine
	AuthorDateLine
	CommitterLine
	CommitterDateLine
	MessageStartLine
	MessageLine
	MessageEndLine
	NotesStartLine
	NotesLine
	NotesEndLine
	DiffLine
	ModeLine
	IndexLine
	FromFileLine
	ToFileLine
	BinaryFileLine
	HunkLineNumberLine
	HunkContentLine
	ParseFailure
)

func (state ParseState) String() string {
	return [...]string{
		"Initial",
		"CommitLine",
		"MergeLine",
		"AuthorLine",
		"AuthorDateLine",
		"CommitterLine",
		"CommitterDateLine",
		"MessageStartLine",
		"MessageLine",
		"MessageEndLine",
		"NotesStartLine",
		"NotesLine",
		"NotesEndLine",
		"DiffLine",
		"ModeLine",
		"IndexLine",
		"FromFileLine",
		"ToFileLine",
		"BinaryFileLine",
		"HunkLineNumberLine",
		"HunkContentLine",
		"ParseFailure",
	}[state]
}

// UseCustomContentWriter sets useCustomContentWriter option.
func UseCustomContentWriter() Option {
	return func(parser *Parser) { parser.useCustomContentWriter = true }
}

// UseLowMemoryScan sets the scan to optimize for limited memory at the cost of speed (currently up to 9%)
func UseLowMemoryScan() Option {
	return func(parser *Parser) {
		parser.lowMemoryScan = true
	}
}

// WithMaxDiffSize sets maxDiffSize option. Diffs larger than maxDiffSize will
// be truncated.
func WithMaxDiffSize(maxDiffSize int64) Option {
	return func(parser *Parser) {
		parser.maxDiffSize = maxDiffSize
	}
}

// WithMaxCommitSize sets maxCommitSize option. Commits larger than maxCommitSize
// will be put in the commit channel and additional diffs will be added to a
// new commit.
func WithMaxCommitSize(maxCommitSize int64) Option {
	return func(parser *Parser) {
		parser.maxCommitSize = maxCommitSize
	}
}

// WithWaitDelay sets the waitDelay option. This specifies how long to wait after
// context cancellation before forcefully killing git processes.
func WithWaitDelay(waitDelay time.Duration) Option {
	return func(parser *Parser) {
		parser.waitDelay = waitDelay
	}
}

// Option is used for adding options to Config.
type Option func(*Parser)

// NewParser creates a GitParse config from options and sets defaults.
func NewParser(options ...Option) *Parser {
	parser := &Parser{
		dateFormat:    defaultDateFormat,
		maxDiffSize:   defaultMaxDiffSize,
		maxCommitSize: defaultMaxCommitSize,
		waitDelay:     defaultWaitDelay,
	}
	for _, option := range options {
		option(parser)
	}
	return parser
}

type gitArgs struct {
	env    []string
	global []string
	log    []string
	show   []string
	paths  []string
}

// RepoPath parses the output of the `git log` command for the `source` path.
// The Diff chan will return diffs in the order they are parsed from the log,
// though the diffs are generated using `git show` in groups.
//
// head and base are commit hashes or refs. When base is non-empty the log is
// restricted to the range base..head (commits reachable from head but not from
// base), which is the diff-scan contract behind `--since-commit`. The range is
// computed by git itself so that it is independent of commit dates and merge
// topology. An empty base means a full-history scan of head (or of --all when
// head is also empty). An empty head with a non-empty base means every commit
// reachable from any ref but not from base (`--all ^base`), which is what
// `--since-commit X` without `--branch` has always covered; callers that want
// a single-branch diff pass the head explicitly.
func (c *Parser) RepoPath(
	ctx context.Context,
	source string,
	head string,
	base string,
	excludedGlobs []string,
	isBare bool,
) (chan *Diff, error) {
	args := c.prepGitArgs(source, head, base, excludedGlobs, isBare)

	if c.lowMemoryScan {
		return c.repoPathLowMemory(ctx, args)
	}

	showCmd := exec.CommandContext(ctx,
		"git",
		slices.Concat(args.global, []string{"log"}, args.show, args.log, args.paths)...,
	)
	showCmd.Env = args.env

	return c.executeCommand(ctx, showCmd, false)
}

func (c *Parser) repoPathLowMemory(ctx context.Context, args gitArgs) (chan *Diff, error) {
	commitGroups, err := c.enumerateCommits(ctx, args)
	if err != nil {
		return nil, err
	}

	// c.executeCommand returns a channel that is later closed by a
	// different goroutine after the command finishes, but we're not
	// running a single command anymore. we'll use a channel of channels to
	// reduce back to one channel we return to our caller.  Unbuffered so
	// we have at most one git log running and one git log draining.
	diffGroups := make(chan chan *Diff)
	go func() {
		defer common.RecoverWithExit(ctx)
		defer close(diffGroups)

		for group := range commitGroups {
			if common.IsDone(ctx) {
				return
			}

			// `git log` over an explicit list, not `git show`. The two print the
			// same thing for ordinary commits, but only log applies --diff-filter
			// to whole commits, so this is what keeps the set of scanned commits
			// the same as the single-command form.
			logCmd := exec.CommandContext(ctx,
				"git",
				slices.Concat(
					args.global, []string{"log"}, args.show,
					[]string{
						// Keep the commits in the order rev-list gave them. Plain
						// --no-walk would re-sort each group by commit date, which
						// scrambles the order across groups.
						"--no-walk=unsorted",
						// Hashes come in on stdin, so the group size is ours to pick.
						"--stdin",
					},
					args.paths,
				)...,
			)
			logCmd.Env = args.env
			logCmd.Stdin = strings.NewReader(strings.Join(group, "\n") + "\n")

			diffGroup, err := c.executeCommand(ctx, logCmd, false)
			if err != nil {
				ctx.Logger().Error(err, "Error executing git log for commit group.")
				return
			}
			err = common.CancellableWrite(ctx, diffGroups, diffGroup)
			if err != nil {
				ctx.Logger().Error(err, "git log iteration cancelled")
				return
			}
		}
	}()

	// and this is the single channel we're responsible for returning and
	// closing.
	diffChan := make(chan *Diff)
	go func() {
		defer common.RecoverWithExit(ctx)
		defer close(diffChan)

		var err error
		for groupdiffs := range diffGroups {
			for diff := range groupdiffs {
				err = common.CancellableWrite(ctx, diffChan, diff)
				if err != nil {
					return // context cancel
				}
			}
		}
	}()

	return diffChan, nil
}

// enumerateCommits asks git for the hashes of the commits we mean to scan, and
// nothing else. It returns them in groups, so patch generation can start before the
// whole history has been walked.
//
// This uses `git rev-list` rather than `git log`. rev-list is the plumbing command for
// listing commits and never sets up git's diff machinery, which `git log` does as soon
// as a diff option is present. On this repository that is the difference between 43 MB
// and 3.4 MB of peak memory for a phase whose only job is to print hashes, and this is
// the phase that sets the peak on long histories.
// commitGroupSize is how many commits each `git log` gets.
func (c *Parser) commitGroupSize() int {
	// A size of zero or less would mean a group that never fills, so it falls back.
	if c.groupSize <= 0 {
		return logGroupSize
	}
	return c.groupSize
}

func (c *Parser) enumerateCommits(ctx context.Context, args gitArgs) (chan []string, error) {
	// args.log holds only the options that choose commits, so it can go to rev-list
	// as-is. Diff options live in args.show and rev-list would reject them.
	cmd := exec.CommandContext(ctx,
		"git", slices.Concat(
			args.global, []string{"rev-list"},
			args.log,
			args.paths,
		)...)
	cmd.WaitDelay = c.waitDelay
	cmd.Env = args.env

	// Keep stderr, because it carries the reason a bad ref or a broken repo failed.
	var stderr strings.Builder
	cmd.Stderr = &stderr

	stdOut, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to execute git rev-list: %w", err)
	}

	// Wait for the first byte before returning. A bad revision makes rev-list fail
	// immediately, and this is the last moment we can hand that back to the caller as
	// an error. Reporting it any later means closing the channel instead, and a typo in
	// a branch name then looks exactly like an empty repository.
	reader := bufio.NewReader(stdOut)
	if _, err := reader.Peek(1); err != nil {
		if waitErr := cmd.Wait(); waitErr != nil {
			return nil, fmt.Errorf("failed to list commits: %w: %s", waitErr, strings.TrimSpace(stderr.String()))
		}
		if !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("failed to read commit list: %w", err)
		}

		// git was happy and printed nothing, so there is genuinely nothing to scan.
		empty := make(chan []string)
		close(empty)
		return empty, nil
	}

	commitGroups := make(chan []string)
	go func() {
		defer close(commitGroups)
		defer func() {
			if err := cmd.Wait(); err != nil {
				ctx.Logger().Error(err, "git rev-list exited with error", "stderr", strings.TrimSpace(stderr.String()))
			}
		}()

		s := bufio.NewScanner(reader)
		groupSize := c.commitGroupSize()
		commitGroup := make([]string, 0, groupSize)
		for s.Scan() && !common.IsDone(ctx) {
			commitGroup = append(commitGroup, s.Text())
			if len(commitGroup) < groupSize {
				continue
			}
			if err := common.CancellableWrite(ctx, commitGroups, commitGroup); err != nil {
				ctx.Logger().Error(err, "git rev-list stopping early")
				return
			}
			commitGroup = make([]string, 0, groupSize)
		}

		// The last group is almost never exactly full.
		if len(commitGroup) != 0 {
			if err := common.CancellableWrite(ctx, commitGroups, commitGroup); err != nil {
				ctx.Logger().Error(err, "failed to flush last commit group")
			}
		}

		if err := s.Err(); err != nil {
			ctx.Logger().Error(err, "error reading commit list")
		}
	}()

	return commitGroups, nil
}

func (c *Parser) prepGitArgs(source string, head string, base string, excludedGlobs []string, isBare bool) gitArgs {
	// Full-history scans skip deletions; a diff scan must report every change in the range.
	abbreviatedLog := base == ""

	args := gitArgs{
		global: []string{
			"-C", source,
		},
		log: []string{
			// https://git-scm.com/docs/git-log#Documentation/git-log.txt---full-history
			"--full-history",
		},
		show: []string{
			// https://git-scm.com/docs/git-show#Documentation/git-show.txt---patch
			"--patch",
			// https://git-scm.com/docs/git-log#Documentation/git-log.txt---dateformat
			"--date=iso-strict",
			// https://git-scm.com/docs/git-show#_pretty_formats
			"--pretty=fuller",
			// https://git-scm.com/docs/git-show#Documentation/git-show.txt---notesref
			"--notes",
		},
		paths: []string{},
	}

	if abbreviatedLog {
		// Only in show. args.log holds the options that choose commits, and it is
		// also what the lower-memory scan hands to `git rev-list`, which rejects diff
		// options outright. Leaving it out costs nothing: rev-list then lists a few
		// commits whose diffs are all filtered away, and the `git log` that generates
		// the patches drops those commits itself, exactly as the single-command form
		// does.
		// https://git-scm.com/docs/git-show#Documentation/git-show.txt---diff-filterACDMRTUXB
		args.show = append(args.show, "--diff-filter=AM")
	}

	// The positive end of the walk, kept last before the -- (not required but
	// sensible). With no head every ref is walked, so a base-only scan is
	// `--all ^base`: everything since base on any branch, not just the checked
	// out one. The pre-commit hook wants the empty HEAD..HEAD range and passes
	// HEAD as both ends itself (see the isPreCommitHook override in main.go).
	// https://git-scm.com/docs/git-log#Documentation/git-log.txt---all
	switch {
	case head != "":
		args.log = append(args.log, head)
	default:
		args.log = append(args.log, "--all")
	}

	// `head ^base` is base..head. Keeping the two revisions as separate args
	// means head is always the positive end of the range and the base is
	// never spliced into a string git has to parse.
	// https://git-scm.com/docs/gitrevisions#_specifying_ranges
	if base != "" {
		args.log = append(args.log, "^"+base)
	}

	// Pathspecs live in their own slice so `--` always trails every revision.
	if len(excludedGlobs) != 0 {
		args.paths = []string{"--", "."}
		for _, glob := range excludedGlobs {
			// This is not directly doc'd but added in git 1.9.0 and found in pathspec.c
			args.paths = append(args.paths, ":(exclude)"+glob)
		}
	}

	absPath, err := filepath.Abs(source)
	if err == nil {
		if !isBare {
			args.env = append(args.env, "GIT_DIR="+filepath.Join(absPath, ".git"))
		} else {
			args.env = append(args.env, "GIT_DIR="+absPath)
			// We need those variables to handle incoming commits
			// while using trufflehog in pre-receive hooks
			if dir := os.Getenv("GIT_OBJECT_DIRECTORY"); dir != "" {
				args.env = append(args.env, "GIT_OBJECT_DIRECTORY="+dir)
			}
			if dir := os.Getenv("GIT_ALTERNATE_OBJECT_DIRECTORIES"); dir != "" {
				args.env = append(args.env, "GIT_ALTERNATE_OBJECT_DIRECTORIES="+dir)
			}
		}
	}
	return args
}

// Staged parses the output of the `git diff` command for the `source` path.
func (c *Parser) Staged(ctx context.Context, source string) (chan *Diff, error) {
	// Provide the --cached flag to diff to get the diff of the staged changes.
	args := []string{"-C", source, "diff", "-p", "--cached", "--full-history", "--diff-filter=AM", "--date=iso-strict"}

	cmd := exec.CommandContext(ctx, "git", args...)

	absPath, err := filepath.Abs(source)
	if err == nil {
		cmd.Env = append(cmd.Env, "GIT_DIR="+filepath.Join(absPath, ".git"))
	}

	return c.executeCommand(ctx, cmd, true)
}

// executeCommand runs an exec.Cmd, reads stdout and stderr, and waits for the Cmd to complete.
// waitDelay specifies how long to wait after context cancellation before forcefully killing the process.
func (c *Parser) executeCommand(ctx context.Context, cmd *exec.Cmd, isStaged bool) (chan *Diff, error) {
	diffChan := make(chan *Diff, 64)

	stdOut, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stdErr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}

	// Set WaitDelay to allow the command additional time to exit after context cancellation
	cmd.WaitDelay = c.waitDelay

	err = cmd.Start()
	if err != nil {
		return nil, err
	}

	go func() {
		scanner := bufio.NewScanner(stdErr)
		for scanner.Scan() {
			ctx.Logger().V(2).Info(scanner.Text())
		}
	}()

	go func() {
		defer func() {
			if err := cmd.Wait(); err != nil {
				ctx.Logger().V(2).Info("Error waiting for git command to complete.", "error", err)
			}
		}()
		c.FromReader(ctx, stdOut, diffChan, isStaged)
		if err := stdOut.Close(); err != nil {
			ctx.Logger().V(2).Info("Error closing git stdout pipe.", "error", err)
		}
	}()

	return diffChan, nil
}

func (c *Parser) FromReader(ctx context.Context, stdOut io.Reader, diffChan chan *Diff, isStaged bool) {
	outReader := bufio.NewReader(stdOut)
	var (
		currentCommit *Commit

		totalLogSize int
	)
	latestState := Initial

	diff := func(c *Commit, opts ...diffOption) *Diff {
		opts = append(opts, withCustomContentWriter(bufferwriter.New()))
		return newDiff(c, opts...)
	}
	if c.useCustomContentWriter {
		diff = func(c *Commit, opts ...diffOption) *Diff {
			opts = append(opts, withCustomContentWriter(bufferedfilewriter.New()))
			return newDiff(c, opts...)
		}
	}
	currentDiff := diff(currentCommit)

	defer common.RecoverWithExit(ctx)
	defer close(diffChan)
	for !common.IsDone(ctx) {

		line, err := outReader.ReadBytes([]byte("\n")[0])
		if err != nil && len(line) == 0 {
			break
		}

		switch {
		case isCommitLine(isStaged, latestState, line):
			latestState = CommitLine

			// If there is a currentDiff, add it to currentCommit.
			if currentDiff.Len() > 0 || currentDiff.IsBinary {
				if err := currentDiff.finalize(); err != nil {
					ctx.Logger().Error(
						err,
						"failed to finalize diff",
						"commit", currentCommit.Hash,
						"diff", currentDiff.PathB,
						"size", currentDiff.Len(),
						"latest_state", latestState.String(),
					)
				}
				diffChan <- currentDiff
				currentCommit.Size += currentDiff.Len()
				currentCommit.hasDiffs = true
			}
			// If there is a currentCommit, send it to the channel.
			if currentCommit != nil {
				totalLogSize += currentCommit.Size
				if !currentCommit.hasDiffs {
					// Initialize an empty Diff instance associated with the given commit.
					// Since this diff represents "no changes", we only need to set the commit.
					// This is required to ensure commits that have no diffs are still processed.
					diffChan <- &Diff{Commit: currentCommit}
				}
			}

			// Create a new currentDiff and currentCommit
			currentCommit = &Commit{Message: strings.Builder{}}
			currentDiff = diff(currentCommit)
			// Check that the commit line contains a hash and set it.
			if len(line) >= 47 {
				currentCommit.Hash = string(line[7:47])
			}
		case isMergeLine(isStaged, latestState, line):
			latestState = MergeLine
		case isAuthorLine(isStaged, latestState, line):
			latestState = AuthorLine
			currentCommit.Author = strings.TrimSpace(string(line[8:]))
		case isAuthorDateLine(isStaged, latestState, line):
			latestState = AuthorDateLine

			date, err := time.Parse(c.dateFormat, strings.TrimSpace(string(line[12:])))
			if err != nil {
				ctx.Logger().Error(err, "failed to parse commit date", "commit", currentCommit.Hash, "latestState", latestState.String())
				latestState = ParseFailure
				continue
			}
			currentCommit.Date = date
		case isCommitterLine(isStaged, latestState, line):
			latestState = CommitterLine
			currentCommit.Committer = strings.TrimSpace(string(line[8:]))
		case isCommitterDateLine(isStaged, latestState, line):
			latestState = CommitterDateLine
			// NoOp
		case isMessageStartLine(isStaged, latestState, line):
			latestState = MessageStartLine
			// NoOp
		case isMessageLine(isStaged, latestState, line):
			latestState = MessageLine
			currentCommit.Message.Write(line[4:]) // Messages are indented by 4 spaces.

		case isMessageEndLine(isStaged, latestState, line):
			latestState = MessageEndLine
			// NoOp
		case isNotesStartLine(isStaged, latestState, line):
			latestState = NotesStartLine

			currentCommit.Message.WriteString("\n")
			currentCommit.Message.Write(line)
		case isNotesLine(isStaged, latestState, line):
			latestState = NotesLine
			currentCommit.Message.Write(line[4:]) // Notes are indented by 4 spaces.
		case isNotesEndLine(isStaged, latestState, line):
			latestState = NotesEndLine
			// NoOp
		case isDiffLine(isStaged, latestState, line):
			latestState = DiffLine

			if currentDiff.Len() > 0 || currentDiff.IsBinary {
				if err := currentDiff.finalize(); err != nil {
					ctx.Logger().Error(err,
						"failed to finalize diff",
						"commit", currentCommit.Hash,
						"diff", currentDiff.PathB,
						"size", currentDiff.Len(),
						"latest_state", latestState.String(),
					)
				}
				diffChan <- currentDiff
				currentCommit.hasDiffs = true
			}

			// This should never be nil, but check in case the stdin stream is messed up.
			if currentCommit == nil {
				currentCommit = &Commit{}
			}
			currentDiff = diff(currentCommit)
		case isModeLine(latestState, line):
			latestState = ModeLine
			// NoOp
		case isIndexLine(latestState, line):
			latestState = IndexLine
			// NoOp
		case isBinaryLine(latestState, line):
			latestState = BinaryFileLine

			path, ok := pathFromBinaryLine(line)
			if !ok {
				err = fmt.Errorf(`expected line to match 'Binary files a/fileA and b/fileB differ', got "%s"`, line)
				ctx.Logger().Error(err, "Failed to parse BinaryFileLine")
				latestState = ParseFailure
				continue
			}

			// Don't do anything if the file is deleted. (pathA has file path, pathB is /dev/null)
			if path != "" {
				currentDiff.PathB = path
				currentDiff.IsBinary = true
			}
		case isFromFileLine(latestState, line):
			latestState = FromFileLine
			// NoOp
		case isToFileLine(latestState, line):
			latestState = ToFileLine

			path, ok := pathFromToFileLine(line)
			if !ok {
				err = fmt.Errorf(`expected line to match format '+++ b/path/to/file.go', got '%s'`, line)
				ctx.Logger().Error(err, "Failed to parse ToFileLine")
				latestState = ParseFailure
				continue
			}

			currentDiff.PathB = path
		case isHunkLineNumberLine(latestState, line):
			latestState = HunkLineNumberLine

			if currentDiff.Len() > 0 || currentDiff.IsBinary {
				if err := currentDiff.finalize(); err != nil {
					ctx.Logger().Error(
						err,
						"failed to finalize diff",
						"commit", currentCommit.Hash,
						"diff", currentDiff.PathB,
						"size", currentDiff.Len(),
						"latest_state", latestState.String(),
					)
				}
				diffChan <- currentDiff
			}
			currentDiff = diff(currentCommit, withPathB(currentDiff.PathB))

			words := bytes.Split(line, []byte(" "))
			if len(words) >= 3 {
				startSlice := bytes.Split(words[2], []byte(","))
				lineStart, err := strconv.Atoi(string(startSlice[0]))
				if err == nil {
					currentDiff.LineStart = lineStart
				}
			}
		case isHunkContextLine(latestState, line):
			if latestState != HunkContentLine {
				latestState = HunkContentLine
			}
			// TODO: Why do we care about this? It creates empty lines in the diff. If there are no plusLines, it's just newlines.
			if err := currentDiff.write([]byte("\n")); err != nil {
				ctx.Logger().Error(err, "failed to write to diff")
			}
		case isHunkPlusLine(latestState, line):
			if latestState != HunkContentLine {
				latestState = HunkContentLine
			}

			if err := currentDiff.write(line[1:]); err != nil {
				ctx.Logger().Error(err, "failed to write to diff")
			}
			// NoOp. We only care about additions.
		case isHunkMinusLine(latestState, line),
			isHunkNewlineWarningLine(latestState, line),
			isHunkEmptyLine(latestState, line):
			if latestState != HunkContentLine {
				latestState = HunkContentLine
			}
			// NoOp
		case isCommitSeparatorLine(latestState, line):
			// NoOp
		default:
			// Skip ahead until we find the next diff or commit.
			if latestState == ParseFailure {
				continue
			}

			// Here be dragons...
			// Build an informative error message.
			err := fmt.Errorf(`invalid line "%s" after state "%s"`, line, latestState)
			var logger logr.Logger
			if currentCommit != nil && currentCommit.Hash != "" {
				logger = ctx.Logger().WithValues("commit", currentCommit.Hash)
			} else {
				logger = ctx.Logger()
			}
			logger.Error(err, "failed to parse Git input. Recovering at the latest commit or diff...")

			latestState = ParseFailure
		}

		if int64(currentDiff.Len()) > c.maxDiffSize {
			ctx.Logger().V(2).Info(fmt.Sprintf(
				"Diff for %s exceeded MaxDiffSize(%d)", currentDiff.PathB, c.maxDiffSize,
			))
			break
		}
	}
	cleanupParse(ctx, currentCommit, currentDiff, diffChan, &totalLogSize)

	ctx.Logger().V(2).Info("finished parsing git log.", "total_log_size", totalLogSize)
}

func isMergeLine(isStaged bool, latestState ParseState, line []byte) bool {
	if isStaged || latestState != CommitLine {
		return false
	}
	if len(line) > 6 && bytes.Equal(line[:6], []byte("Merge:")) {
		return true
	}
	return false
}

// commit 7a95bbf0199e280a0e42dbb1d1a3f56cdd0f6e05
func isCommitLine(isStaged bool, latestState ParseState, line []byte) bool {
	if isStaged || (latestState != Initial &&
		latestState != MessageStartLine &&
		latestState != MessageEndLine &&
		latestState != ModeLine &&
		latestState != IndexLine &&
		latestState != BinaryFileLine &&
		latestState != ToFileLine &&
		latestState != HunkContentLine &&
		latestState != ParseFailure) {
		return false
	}

	if len(line) > 7 && bytes.Equal(line[:7], []byte("commit ")) {
		return true
	}
	return false
}

// Author: Bill Rich <bill.rich@trufflesec.com>
func isAuthorLine(isStaged bool, latestState ParseState, line []byte) bool {
	if isStaged || (latestState != CommitLine && latestState != MergeLine) {
		return false
	}
	if len(line) > 8 && bytes.Equal(line[:7], []byte("Author:")) {
		return true
	}
	return false
}

// AuthorDate: 2021-08-10T15:20:40+01:00
func isAuthorDateLine(isStaged bool, latestState ParseState, line []byte) bool {
	if isStaged || latestState != AuthorLine {
		return false
	}
	if len(line) > 10 && bytes.Equal(line[:11], []byte("AuthorDate:")) {
		return true
	}
	return false
}

// Commit: Bill Rich <bill.rich@trufflesec.com>
func isCommitterLine(isStaged bool, latestState ParseState, line []byte) bool {
	if isStaged || latestState != AuthorDateLine {
		return false
	}
	if len(line) > 8 && bytes.Equal(line[:7], []byte("Commit:")) {
		return true
	}
	return false
}

// CommitDate: Wed Apr 17 19:59:28 2024 -0400
func isCommitterDateLine(isStaged bool, latestState ParseState, line []byte) bool {
	if isStaged || latestState != CommitterLine {
		return false
	}
	if len(line) > 10 && bytes.Equal(line[:11], []byte("CommitDate:")) {
		return true
	}
	return false
}

// Line directly after CommitterDate with only a newline.
func isMessageStartLine(isStaged bool, latestState ParseState, line []byte) bool {
	if isStaged || latestState != CommitterDateLine {
		return false
	}
	// TODO: Improve the implementation of this and isMessageEndLine
	if len(strings.TrimRight(string(line[:]), "\r\n")) == 0 {
		return true
	}
	return false
}

// Line that starts with 4 spaces
func isMessageLine(isStaged bool, latestState ParseState, line []byte) bool {
	if isStaged || (latestState != MessageStartLine && latestState != MessageLine) {
		return false
	}
	if len(line) > 4 && bytes.Equal(line[:4], []byte("    ")) {
		return true
	}
	return false
}

// Line directly after MessageLine with only a newline.
func isMessageEndLine(isStaged bool, latestState ParseState, line []byte) bool {
	if isStaged || latestState != MessageLine {
		return false
	}
	if len(strings.TrimRight(string(line[:]), "\r\n")) == 0 {
		return true
	}
	return false
}

// `Notes:` or `Notes (context):`
// See https://tylercipriani.com/blog/2022/11/19/git-notes-gits-coolest-most-unloved-feature/
func isNotesStartLine(isStaged bool, latestState ParseState, line []byte) bool {
	if isStaged || latestState != MessageEndLine {
		return false
	}
	if len(line) > 5 && bytes.Equal(line[:5], []byte("Notes")) {
		return true
	}
	return false
}

// Line after NotesStartLine that starts with 4 spaces
func isNotesLine(isStaged bool, latestState ParseState, line []byte) bool {
	if isStaged || (latestState != NotesStartLine && latestState != NotesLine) {
		return false
	}
	if len(line) > 4 && bytes.Equal(line[:4], []byte("    ")) {
		return true
	}
	return false
}

// Line directly after NotesLine with only a newline.
func isNotesEndLine(isStaged bool, latestState ParseState, line []byte) bool {
	if isStaged || latestState != NotesLine {
		return false
	}
	if len(strings.TrimRight(string(line[:]), "\r\n")) == 0 {
		return true
	}
	return false
}

// diff --git a/internal/addrs/move_endpoint_module.go b/internal/addrs/move_endpoint_module.go
func isDiffLine(isStaged bool, latestState ParseState, line []byte) bool {
	if latestState != MessageStartLine &&
		latestState != MessageEndLine &&
		latestState != NotesEndLine &&
		latestState != BinaryFileLine &&
		latestState != ModeLine &&
		latestState != IndexLine &&
		latestState != HunkContentLine &&
		latestState != ParseFailure {
		if !isStaged || latestState != Initial {
			return false
		}
	}
	if len(line) > 11 && bytes.Equal(line[:11], []byte("diff --git ")) {
		return true
	}
	return false
}

// old mode 100644
// new mode 100755
// new file mode 100644
// similarity index 100%
// rename from old.txt
// rename to new.txt
// deleted file mode 100644
func isModeLine(latestState ParseState, line []byte) bool {
	if latestState != DiffLine && latestState != ModeLine {
		return false
	}
	// This could probably be better written.
	if (len(line) > 17 && bytes.Equal(line[:17], []byte("deleted file mode"))) ||
		(len(line) > 16 && bytes.Equal(line[:16], []byte("similarity index"))) ||
		(len(line) > 13 && bytes.Equal(line[:13], []byte("new file mode"))) ||
		(len(line) > 11 && bytes.Equal(line[:11], []byte("rename from"))) ||
		(len(line) > 9 && bytes.Equal(line[:9], []byte("rename to"))) ||
		(len(line) > 8 && bytes.Equal(line[:8], []byte("old mode"))) ||
		(len(line) > 8 && bytes.Equal(line[:8], []byte("new mode"))) {
		return true
	}
	return false
}

// index 1ed6fbee1..aea1e643a 100644
// index 00000000..e69de29b
func isIndexLine(latestState ParseState, line []byte) bool {
	if latestState != DiffLine && latestState != ModeLine {
		return false
	}
	if len(line) > 6 && bytes.Equal(line[:6], []byte("index ")) {
		return true
	}
	return false
}

// Binary files /dev/null and b/plugin.sig differ
func isBinaryLine(latestState ParseState, line []byte) bool {
	if latestState != IndexLine {
		return false
	}
	if len(line) > 7 && bytes.Equal(line[:6], []byte("Binary")) {
		return true
	}
	return false
}

// Get the b/ file path. Ignoring the edge case of files having `and /b` in the name for simplicity.
func pathFromBinaryLine(line []byte) (string, bool) {
	if bytes.Contains(line, []byte("and /dev/null")) {
		return "", true
	}
	line = bytes.TrimSuffix(line, []byte("\n"))

	var (
		path string
		err  error
	)
	if _, after, ok := bytes.Cut(line, []byte(" and b/")); ok {
		pathBytes, ok := bytes.CutSuffix(after, []byte(" differ"))
		if !ok {
			return "", false
		}
		path = string(pathBytes)
	} else if _, after, ok = bytes.Cut(line, []byte(` and "b/`)); ok {
		// Edge case where the path is quoted.
		// https://github.com/trufflesecurity/trufflehog/issues/2384

		// Drop the `" differ` and handle escaped characters in the path.
		// e.g., "\342\200\224" instead of "—".
		// See https://github.com/trufflesecurity/trufflehog/issues/2418
		pathBytes, ok := bytes.CutSuffix(after, []byte(`" differ`))
		if !ok {
			return "", false
		}
		path, err = strconv.Unquote(`"` + string(pathBytes) + `"`)
		if err != nil {
			return "", false
		}
	} else {
		// Unknown format.
		return "", false
	}

	return path, true
}

// --- a/internal/addrs/move_endpoint_module.go
// --- /dev/null
func isFromFileLine(latestState ParseState, line []byte) bool {
	if latestState != IndexLine && latestState != ModeLine {
		return false
	}
	if len(line) >= 6 && bytes.Equal(line[:4], []byte("--- ")) {
		return true
	}
	return false
}

// +++ b/internal/addrs/move_endpoint_module.go
func isToFileLine(latestState ParseState, line []byte) bool {
	if latestState != FromFileLine {
		return false
	}
	if len(line) >= 6 && bytes.Equal(line[:4], []byte("+++ ")) {
		return true
	}
	return false
}

// Get the b/ file path.
func pathFromToFileLine(line []byte) (string, bool) {
	// Normalize paths, as they can end in `\n`, `\t\n`, etc.
	// See https://github.com/trufflesecurity/trufflehog/issues/1060
	line = bytes.TrimSpace(line)

	// File was deleted.
	if bytes.Equal(line, []byte("+++ /dev/null")) {
		return "", true
	}

	var (
		path string
		err  error
	)
	if _, after, ok := bytes.Cut(line, []byte("+++ b/")); ok {
		path = string(after)
	} else if _, after, ok = bytes.Cut(line, []byte(`+++ "b/`)); ok {
		// Edge case where the path is quoted.
		// e.g., `+++ "b/C++/1 \320\243\321\200\320\276\320\272/B.c"`

		// Drop the trailing `"` and handle escaped characters in the path
		// e.g., "\342\200\224" instead of "—".
		// See https://github.com/trufflesecurity/trufflehog/issues/2418
		path, err = strconv.Unquote(`"` + string(after[:len(after)-1]) + `"`)
		if err != nil {
			return "", false
		}
	} else {
		// Unknown format.
		return "", false
	}

	return path, true
}

// @@ -298 +298 @@ func maxRetryErrorHandler(resp *http.Response, err error, numTries int)
func isHunkLineNumberLine(latestState ParseState, line []byte) bool {
	if latestState != ToFileLine && latestState != HunkContentLine {
		return false
	}
	if len(line) >= 8 && bytes.Equal(line[:2], []byte("@@")) {
		return true
	}
	return false
}

// fmt.Println("ok")
// (There's a space before `fmt` that gets removed by the formatter.)
func isHunkContextLine(latestState ParseState, line []byte) bool {
	if latestState != HunkLineNumberLine && latestState != HunkContentLine {
		return false
	}
	if len(line) >= 1 && bytes.Equal(line[:1], []byte(" ")) {
		return true
	}
	return false
}

// +fmt.Println("ok")
func isHunkPlusLine(latestState ParseState, line []byte) bool {
	if latestState != HunkLineNumberLine && latestState != HunkContentLine {
		return false
	}
	if len(line) >= 1 && bytes.Equal(line[:1], []byte("+")) {
		return true
	}
	return false
}

// -fmt.Println("ok")
func isHunkMinusLine(latestState ParseState, line []byte) bool {
	if latestState != HunkLineNumberLine && latestState != HunkContentLine {
		return false
	}
	if len(line) >= 1 && bytes.Equal(line[:1], []byte("-")) {
		return true
	}
	return false
}

// \ No newline at end of file
func isHunkNewlineWarningLine(latestState ParseState, line []byte) bool {
	if latestState != HunkContentLine {
		return false
	}
	if len(line) >= 27 && bytes.Equal(line[:27], []byte("\\ No newline at end of file")) {
		return true
	}
	return false
}

// Newline after hunk, or an empty line, e.g.
// +}
//
// commit 00920984e3435057f09cee5468850f7546dfa637 (tag: v3.42.0)
func isHunkEmptyLine(latestState ParseState, line []byte) bool {
	if latestState != HunkLineNumberLine && latestState != HunkContentLine {
		return false
	}
	// TODO: Can this also be `\n\r`?
	if len(line) == 1 && bytes.Equal(line[:1], []byte("\n")) {
		return true
	}
	return false
}

func isCommitSeparatorLine(latestState ParseState, line []byte) bool {
	if (latestState == ModeLine || latestState == IndexLine || latestState == BinaryFileLine || latestState == ToFileLine) &&
		len(line) == 1 && bytes.Equal(line[:1], []byte("\n")) {
		return true
	}
	return false
}

func cleanupParse(ctx context.Context, currentCommit *Commit, currentDiff *Diff, diffChan chan *Diff, totalLogSize *int) {
	if err := currentDiff.finalize(); err != nil {
		ctx.Logger().Error(err, "failed to finalize diff")
		return
	}

	// Ignore empty or binary diffs (this condition may be redundant).
	if currentDiff != nil && (currentDiff.Len() > 0 || currentDiff.IsBinary) {
		currentDiff.Commit = currentCommit
		diffChan <- currentDiff
		if currentCommit != nil {
			currentCommit.hasDiffs = true
		}
	}

	if currentCommit == nil {
		return
	}
	if totalLogSize != nil {
		*totalLogSize += currentCommit.Size
	}

	// A commit is normally finished off in the loop above, when the next commit line
	// shows up. The last commit in the stream never gets that, so it is finished here
	// instead, and it needs the same rule: a commit with no diffs of its own still has
	// a message, an author and notes worth scanning, so it goes out on its own.
	//
	// Staged diffs come through here too and carry no commit, hence the hash check.
	if !currentCommit.hasDiffs && currentCommit.Hash != "" {
		diffChan <- &Diff{Commit: currentCommit}
	}
}
