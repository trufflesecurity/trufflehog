package gitparse

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

const (
	// defaultDateFormat is the standard date format for git.
	defaultDateFormat = "Mon Jan 02 15:04:05 2006 -0700"

	// defaultMaxDiffSize is the maximum size for a diff. Larger diffs will be cut off.
	defaultMaxDiffSize = 1 * 1024 * 1024 * 1024 // 1GB

	// defaultMaxCommitSize is the maximum size for a commit. Larger commits will be cut off.
	defaultMaxCommitSize = 1 * 1024 * 1024 * 1024 // 1GB
)

// Commit contains commit header info and diffs.
type Commit struct {
	Hash    string
	Author  string
	Date    time.Time
	Message strings.Builder
	Diffs   []Diff
	Size    int // in bytes
}

// Diff contains the info about a file diff in a commit.
type Diff struct {
	PathB     string
	LineStart int
	Content   bytes.Buffer
	IsBinary  bool
}

// Parser sets values used in GitParse.
type Parser struct {
	maxDiffSize   int
	maxCommitSize int
	dateFormat    string
}

type ParseState int

const (
	Initial ParseState = iota
	CommitLine
	MergeLine
	AuthorLine
	DateLine
	MessageStartLine
	MessageLine
	MessageEndLine
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
		"DateLine",
		"MessageStartLine",
		"MessageLine",
		"MessageEndLine",
		"DiffLine",
		"ModeLine",
		"IndexLine",
		"FromFileLine",
		"ToFileLine",
		"BinaryFileLine",
		"HunkLineNumberLine",
		"HunkContentLine",
	}[state]
}

// WithMaxDiffSize sets maxDiffSize option. Diffs larger than maxDiffSize will
// be truncated.
func WithMaxDiffSize(maxDiffSize int) Option {
	return func(parser *Parser) {
		parser.maxDiffSize = maxDiffSize
	}
}

// WithMaxCommitSize sets maxCommitSize option. Commits larger than maxCommitSize
// will be put in the commit channel and additional diffs will be added to a
// new commit.
func WithMaxCommitSize(maxCommitSize int) Option {
	return func(parser *Parser) {
		parser.maxCommitSize = maxCommitSize
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
	}
	for _, option := range options {
		option(parser)
	}
	return parser
}

// Equal compares the content of two Commits to determine if they are the same.
func (c1 *Commit) Equal(c2 *Commit) bool {
	switch {
	case c1.Hash != c2.Hash:
		return false
	case c1.Author != c2.Author:
		return false
	case !c1.Date.Equal(c2.Date):
		return false
	case c1.Message.String() != c2.Message.String():
		return false
	case len(c1.Diffs) != len(c2.Diffs):
		return false
	}
	for i := range c1.Diffs {
		d1 := c1.Diffs[i]
		d2 := c2.Diffs[i]
		switch {
		case d1.PathB != d2.PathB:
			return false
		case d1.LineStart != d2.LineStart:
			return false
		case d1.Content.String() != d2.Content.String():
			return false
		case d1.IsBinary != d2.IsBinary:
			return false
		}
	}
	return true

}

// RepoPath parses the output of the `git log` command for the `source` path.
func (c *Parser) RepoPath(ctx context.Context, source string, head string, abbreviatedLog bool, excludedGlobs []string, isBare bool) (chan Commit, error) {
	args := []string{"-C", source, "log", "-p", "--full-history", "--date=format:%a %b %d %H:%M:%S %Y %z"}
	if abbreviatedLog {
		args = append(args, "--diff-filter=AM")
	}
	if head != "" {
		args = append(args, head)
	} else {
		args = append(args, "--all")
	}
	for _, glob := range excludedGlobs {
		args = append(args, "--", ".", fmt.Sprintf(":(exclude)%s", glob))
	}

	cmd := exec.Command("git", args...)
	absPath, err := filepath.Abs(source)
	if err == nil {
		if !isBare {
			cmd.Env = append(cmd.Env, "GIT_DIR="+filepath.Join(absPath, ".git"))
		} else {
			cmd.Env = append(cmd.Env,
				"GIT_DIR="+absPath,
			)
			// We need those variables to handle incoming commits
			// while using trufflehog in pre-receive hooks
			if dir := os.Getenv("GIT_OBJECT_DIRECTORY"); dir != "" {
				cmd.Env = append(cmd.Env, "GIT_OBJECT_DIRECTORY="+dir)
			}
			if dir := os.Getenv("GIT_ALTERNATE_OBJECT_DIRECTORIES"); dir != "" {
				cmd.Env = append(cmd.Env, "GIT_ALTERNATE_OBJECT_DIRECTORIES="+dir)
			}
		}
	}

	return c.executeCommand(ctx, cmd, false)
}

// Staged parses the output of the `git diff` command for the `source` path.
func (c *Parser) Staged(ctx context.Context, source string) (chan Commit, error) {
	// Provide the --cached flag to diff to get the diff of the staged changes.
	args := []string{"-C", source, "diff", "-p", "--cached", "--full-history", "--diff-filter=AM", "--date=format:%a %b %d %H:%M:%S %Y %z"}

	cmd := exec.Command("git", args...)

	absPath, err := filepath.Abs(source)
	if err == nil {
		cmd.Env = append(cmd.Env, fmt.Sprintf("GIT_DIR=%s", filepath.Join(absPath, ".git")))
	}

	return c.executeCommand(ctx, cmd, true)
}

// executeCommand runs an exec.Cmd, reads stdout and stderr, and waits for the Cmd to complete.
func (c *Parser) executeCommand(ctx context.Context, cmd *exec.Cmd, isStaged bool) (chan Commit, error) {
	commitChan := make(chan Commit, 64)

	stdOut, err := cmd.StdoutPipe()
	if err != nil {
		return commitChan, err
	}
	stdErr, err := cmd.StderrPipe()
	if err != nil {
		return commitChan, err
	}

	err = cmd.Start()
	if err != nil {
		return commitChan, err
	}

	go func() {
		scanner := bufio.NewScanner(stdErr)
		for scanner.Scan() {
			ctx.Logger().V(2).Info(scanner.Text())
		}
	}()

	go func() {
		c.FromReader(ctx, stdOut, commitChan, isStaged)
		if err := cmd.Wait(); err != nil {
			ctx.Logger().V(2).Info("Error waiting for git command to complete.", "error", err)
		}
	}()

	return commitChan, nil
}

func (c *Parser) FromReader(ctx context.Context, stdOut io.Reader, commitChan chan Commit, isStaged bool) {
	outReader := bufio.NewReader(stdOut)
	var (
		currentCommit *Commit
		currentDiff   Diff

		totalLogSize int
	)
	var latestState = Initial

	defer common.RecoverWithExit(ctx)
	defer close(commitChan)
	for {
		if common.IsDone(ctx) {
			break
		}

		line, err := outReader.ReadBytes([]byte("\n")[0])
		if err != nil && len(line) == 0 {
			break
		}

		switch {
		case isCommitLine(isStaged, latestState, line):
			latestState = CommitLine

			// If there is a currentDiff, add it to currentCommit.
			if currentDiff.Content.Len() > 0 {
				currentCommit.Diffs = append(currentCommit.Diffs, currentDiff)
				currentCommit.Size += currentDiff.Content.Len()
			}
			// If there is a currentCommit, send it to the channel.
			if currentCommit != nil {
				commitChan <- *currentCommit
				totalLogSize += currentCommit.Size
			}
			// Create a new currentDiff and currentCommit
			currentDiff = Diff{}
			currentCommit = &Commit{
				Message: strings.Builder{},
			}
			// Check that the commit line contains a hash and set it.
			if len(line) >= 47 {
				currentCommit.Hash = string(line[7:47])
			}
		case isMergeLine(isStaged, latestState, line):
			latestState = MergeLine
		case isAuthorLine(isStaged, latestState, line):
			latestState = AuthorLine

			currentCommit.Author = strings.TrimRight(string(line[8:]), "\n")
		case isDateLine(isStaged, latestState, line):
			latestState = DateLine

			date, err := time.Parse(c.dateFormat, strings.TrimSpace(string(line[6:])))
			if err != nil {
				ctx.Logger().V(2).Info("Could not parse date from git stream.", "error", err)
			}
			currentCommit.Date = date
		case isMessageStartLine(isStaged, latestState, line):
			latestState = MessageStartLine
			// NoOp
		case isMessageLine(isStaged, latestState, line):
			latestState = MessageLine

			currentCommit.Message.Write(line[4:])
		case isMessageEndLine(isStaged, latestState, line):
			latestState = MessageEndLine
			// NoOp
		case isDiffLine(isStaged, latestState, line):
			latestState = DiffLine

			// This should never be nil, but check in case the stdin stream is messed up.
			if currentCommit == nil {
				currentCommit = &Commit{}
			}
			if currentDiff.Content.Len() > 0 {
				currentCommit.Diffs = append(currentCommit.Diffs, currentDiff)
				// If the currentDiff is over 1GB, drop it into the channel so it isn't held in memory waiting for more commits.
				totalSize := 0
				for _, diff := range currentCommit.Diffs {
					totalSize += diff.Content.Len()
				}
				if totalSize > c.maxCommitSize {
					oldCommit := currentCommit
					commitChan <- *currentCommit
					totalLogSize += currentCommit.Size
					currentCommit = &Commit{
						Hash:    currentCommit.Hash,
						Author:  currentCommit.Author,
						Date:    currentCommit.Date,
						Message: strings.Builder{},
						Diffs:   []Diff{},
					}
					// Message needs to be recreated here otherwise writing to it again will result in a panic.
					currentCommit.Message.WriteString(oldCommit.Message.String())
				}
			}
			currentDiff = Diff{}
		case isModeLine(isStaged, latestState, line):
			latestState = ModeLine
			// NoOp
		case isIndexLine(isStaged, latestState, line):
			latestState = IndexLine
			// NoOp
		case isBinaryLine(isStaged, latestState, line):
			latestState = BinaryFileLine

			currentDiff.IsBinary = true
			currentDiff.PathB = pathFromBinaryLine(line)
		case isFromFileLine(isStaged, latestState, line):
			latestState = FromFileLine
			// NoOp
		case isToFileLine(isStaged, latestState, line):
			latestState = ToFileLine

			// TODO: Is this fix still required?
			currentDiff.PathB = strings.TrimRight(strings.TrimRight(string(line[6:]), "\n"), "\t") // Trim the newline and tab characters. https://github.com/trufflesecurity/trufflehog/issues/1060
		case isHunkLineNumberLine(isStaged, latestState, line):
			latestState = HunkLineNumberLine

			if currentDiff.Content.Len() > 0 {
				currentCommit.Diffs = append(currentCommit.Diffs, currentDiff)
			}
			currentDiff = Diff{
				PathB: currentDiff.PathB,
			}

			words := bytes.Split(line, []byte(" "))
			if len(words) >= 3 {
				startSlice := bytes.Split(words[2], []byte(","))
				lineStart, err := strconv.Atoi(string(startSlice[0]))
				if err == nil {
					currentDiff.LineStart = lineStart
				}
			}
		case isHunkContextLine(isStaged, latestState, line):
			if latestState != HunkContentLine {
				latestState = HunkContentLine
			}
			// TODO: Why do we care about this? It creates empty lines in the diff. If there are no plusLines, it's just newlines.
			currentDiff.Content.Write([]byte("\n"))
		case isHunkPlusLine(isStaged, latestState, line):
			if latestState != HunkContentLine {
				latestState = HunkContentLine
			}

			currentDiff.Content.Write(line[1:])
		case isHunkMinusLine(isStaged, latestState, line):
			if latestState != HunkContentLine {
				latestState = HunkContentLine
			}
			// NoOp. We only care about additions.
		case isHunkNewlineWarningLine(isStaged, latestState, line):
			if latestState != HunkContentLine {
				latestState = HunkContentLine
			}
			// NoOp
		case isHunkEmptyLine(isStaged, latestState, line):
			if latestState != HunkContentLine {
				latestState = HunkContentLine
			}
			// NoOp
		case isCommitSeparatorLine(isStaged, latestState, line):
			// NoOp
		default:
			// Skip ahead until we find the next diff or commit.
			if latestState == ParseFailure {
				continue
			}

			// Here be dragons...
			// Build an informative error message.
			var err error
			if currentCommit != nil && currentCommit.Hash != "" {
				err = fmt.Errorf(`failed to parse line "%s" after state "%s" (commit=%s)`, line, latestState, currentCommit.Hash)
			} else {
				err = fmt.Errorf(`failed to parse line "%s" after state "%s"`, line, latestState)
			}
			ctx.Logger().V(2).Error(err, "Recovering at the latest commit or diff...\n")

			latestState = ParseFailure
		}

		if currentDiff.Content.Len() > c.maxDiffSize {
			ctx.Logger().V(2).Info(fmt.Sprintf(
				"Diff for %s exceeded MaxDiffSize(%d)", currentDiff.PathB, c.maxDiffSize,
			))
			break
		}
	}
	cleanupParse(currentCommit, &currentDiff, commitChan, &totalLogSize)

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
	if isStaged || !(latestState == Initial ||
		latestState == MessageStartLine ||
		latestState == MessageEndLine ||
		latestState == ModeLine ||
		latestState == IndexLine ||
		latestState == BinaryFileLine ||
		latestState == ToFileLine ||
		latestState == HunkContentLine ||
		latestState == ParseFailure) {
		return false
	}

	if len(line) > 7 && bytes.Equal(line[:7], []byte("commit ")) {
		return true
	}
	return false
}

// Author: Bill Rich <bill.rich@trufflesec.com>
func isAuthorLine(isStaged bool, latestState ParseState, line []byte) bool {
	if isStaged || !(latestState == CommitLine || latestState == MergeLine) {
		return false
	}
	if len(line) > 8 && bytes.Equal(line[:7], []byte("Author:")) {
		return true
	}
	return false
}

// Date:   Tue Aug 10 15:20:40 2021 +0100
func isDateLine(isStaged bool, latestState ParseState, line []byte) bool {
	if isStaged || latestState != AuthorLine {
		return false
	}
	if len(line) > 7 && bytes.Equal(line[:5], []byte("Date:")) {
		return true
	}
	return false
}

// Line directly after Date with only a newline.
func isMessageStartLine(isStaged bool, latestState ParseState, line []byte) bool {
	if isStaged || latestState != DateLine {
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
	if isStaged || !(latestState == MessageStartLine || latestState == MessageLine) {
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

// diff --git a/internal/addrs/move_endpoint_module.go b/internal/addrs/move_endpoint_module.go
func isDiffLine(isStaged bool, latestState ParseState, line []byte) bool {
	if !(latestState == MessageStartLine || // Empty commit messages can go from MessageStart->Diff
		latestState == MessageEndLine ||
		latestState == BinaryFileLine ||
		latestState == IndexLine ||
		latestState == HunkContentLine ||
		latestState == ParseFailure) {
		if latestState == Initial && !isStaged {
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
func isModeLine(isStaged bool, latestState ParseState, line []byte) bool {
	if !(latestState == DiffLine || latestState == ModeLine) {
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
func isIndexLine(isStaged bool, latestState ParseState, line []byte) bool {
	if !(latestState == DiffLine || latestState == ModeLine) {
		return false
	}
	if len(line) > 6 && bytes.Equal(line[:6], []byte("index ")) {
		return true
	}
	return false
}

// Binary files /dev/null and b/plugin.sig differ
func isBinaryLine(isStaged bool, latestState ParseState, line []byte) bool {
	if latestState != IndexLine {
		return false
	}
	if len(line) > 7 && bytes.Equal(line[:6], []byte("Binary")) {
		return true
	}
	return false
}

// Get the b/ file path. Ignoring the edge case of files having `and /b` in the name for simplicity.
func pathFromBinaryLine(line []byte) string {
	logger := context.Background().Logger()
	sbytes := bytes.Split(line, []byte(" and b/"))
	if len(sbytes) != 2 {
		logger.V(2).Info("Expected binary line to be in 'Binary files a/fileA and b/fileB differ' format.", "got", line)
		return ""
	}
	bRaw := sbytes[1]
	return string(bRaw[:len(bRaw)-7]) // drop the "b/" and " differ"
}

// --- a/internal/addrs/move_endpoint_module.go
func isFromFileLine(isStaged bool, latestState ParseState, line []byte) bool {
	if latestState != IndexLine {
		return false
	}
	if len(line) >= 6 && bytes.Equal(line[:4], []byte("--- ")) {
		return true
	}
	return false
}

// +++ b/internal/addrs/move_endpoint_module.go
func isToFileLine(isStaged bool, latestState ParseState, line []byte) bool {
	if latestState != FromFileLine {
		return false
	}
	if len(line) >= 6 && bytes.Equal(line[:4], []byte("+++ ")) {
		return true
	}
	return false
}

// @@ -298 +298 @@ func maxRetryErrorHandler(resp *http.Response, err error, numTries int)
func isHunkLineNumberLine(isStaged bool, latestState ParseState, line []byte) bool {
	if !(latestState == ToFileLine || latestState == HunkContentLine) {
		return false
	}
	if len(line) >= 8 && bytes.Equal(line[:2], []byte("@@")) {
		return true
	}
	return false
}

// fmt.Println("ok")
// (There's a space before `fmt` that gets removed by the formatter.)
func isHunkContextLine(isStaged bool, latestState ParseState, line []byte) bool {
	if !(latestState == HunkLineNumberLine || latestState == HunkContentLine) {
		return false
	}
	if len(line) >= 1 && bytes.Equal(line[:1], []byte(" ")) {
		return true
	}
	return false
}

// +fmt.Println("ok")
func isHunkPlusLine(isStaged bool, latestState ParseState, line []byte) bool {
	if !(latestState == HunkLineNumberLine || latestState == HunkContentLine) {
		return false
	}
	if len(line) >= 1 && bytes.Equal(line[:1], []byte("+")) {
		return true
	}
	return false
}

// -fmt.Println("ok")
func isHunkMinusLine(isStaged bool, latestState ParseState, line []byte) bool {
	if !(latestState == HunkLineNumberLine || latestState == HunkContentLine) {
		return false
	}
	if len(line) >= 1 && bytes.Equal(line[:1], []byte("-")) {
		return true
	}
	return false
}

// \ No newline at end of file
func isHunkNewlineWarningLine(isStaged bool, latestState ParseState, line []byte) bool {
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
func isHunkEmptyLine(isStaged bool, latestState ParseState, line []byte) bool {
	if !(latestState == HunkLineNumberLine || latestState == HunkContentLine) {
		return false
	}
	// TODO: Can this also be `\n\r`?
	if len(line) == 1 && bytes.Equal(line[:1], []byte("\n")) {
		return true
	}
	return false
}

func isCommitSeparatorLine(isStaged bool, latestState ParseState, line []byte) bool {
	if (latestState == ModeLine || latestState == IndexLine || latestState == BinaryFileLine || latestState == ToFileLine) &&
		len(line) == 1 && bytes.Equal(line[:1], []byte("\n")) {
		return true
	}
	return false
}

func cleanupParse(currentCommit *Commit, currentDiff *Diff, commitChan chan Commit, totalLogSize *int) {
	// Ignore empty or binary diffs (this condition may be redundant).
	if currentDiff != nil && currentDiff.Content.Len() > 0 {
		currentCommit.Diffs = append(currentCommit.Diffs, *currentDiff)
	}
	if currentCommit != nil {
		commitChan <- *currentCommit
		if totalLogSize != nil {
			*totalLogSize += currentCommit.Size
		}
	}
}
