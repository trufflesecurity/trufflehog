package gitparse

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
)

// DateFormat is the standard date format for git.
const DateFormat = "Mon Jan 02 15:04:05 2006 -0700"

// Commit contains commit header info and diffs.
type Commit struct {
	Hash    string
	Author  string
	Date    time.Time
	Message strings.Builder
	Diffs   []Diff
}

// Diff contains the info about a file diff in a commit.
type Diff struct {
	PathB     string
	LineStart int
	Content   bytes.Buffer
	IsBinary  bool
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
func RepoPath(ctx context.Context, source string, head string) (chan Commit, error) {
	args := []string{"-C", source, "log", "-p", "-U5", "--full-history", "--diff-filter=AM", "--date=format:%a %b %d %H:%M:%S %Y %z"}
	if head != "" {
		args = append(args, head)
	} else {
		args = append(args, "--all")
	}

	cmd := exec.Command("git", args...)

	absPath, err := filepath.Abs(source)
	if err == nil {
		cmd.Env = append(cmd.Env, fmt.Sprintf("GIT_DIR=%s", filepath.Join(absPath, ".git")))
	}

	return executeCommand(ctx, cmd)
}

// Unstaged parses the output of the `git diff` command for the `source` path.
func Unstaged(ctx context.Context, source string) (chan Commit, error) {
	args := []string{"-C", source, "diff", "-p", "-U5", "--full-history", "--diff-filter=AM", "--date=format:%a %b %d %H:%M:%S %Y %z", "HEAD"}

	cmd := exec.Command("git", args...)

	absPath, err := filepath.Abs(source)
	if err == nil {
		cmd.Env = append(cmd.Env, fmt.Sprintf("GIT_DIR=%s", filepath.Join(absPath, ".git")))
	}

	return executeCommand(ctx, cmd)
}

// executeCommand runs an exec.Cmd, reads stdout and stderr, and waits for the Cmd to complete.
func executeCommand(ctx context.Context, cmd *exec.Cmd) (chan Commit, error) {
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
			log.Debug(scanner.Text())
		}
	}()

	go func() {
		FromReader(ctx, stdOut, commitChan)
		if err := cmd.Wait(); err != nil {
			log.WithError(err).Debugf("Error waiting for git command to complete.")
		}
	}()

	return commitChan, nil
}

func FromReader(ctx context.Context, stdOut io.Reader, commitChan chan Commit) {
	outReader := bufio.NewReader(stdOut)
	var currentCommit *Commit
	var currentDiff *Diff

	defer common.RecoverWithExit(ctx)
	for {
		line, err := outReader.ReadBytes([]byte("\n")[0])
		if err != nil && len(line) == 0 {
			break
		}
		switch {
		case isCommitLine(line):
			// If there is a currentDiff, add it to currentCommit.
			if currentDiff != nil && currentDiff.Content.Len() > 0 {
				currentCommit.Diffs = append(currentCommit.Diffs, *currentDiff)
			}
			// If there is a currentCommit, send it to the channel.
			if currentCommit != nil {
				commitChan <- *currentCommit
			}
			// Create a new currentDiff and currentCommit
			currentDiff = &Diff{}
			currentCommit = &Commit{
				Message: strings.Builder{},
			}
			// Check that the commit line contains a hash and set it.
			if len(line) >= 47 {
				currentCommit.Hash = string(line[7:47])
			}
		case isAuthorLine(line):
			currentCommit.Author = strings.TrimRight(string(line[8:]), "\n")
		case isDateLine(line):
			date, err := time.Parse(DateFormat, strings.TrimSpace(string(line[6:])))
			if err != nil {
				log.WithError(err).Debug("Could not parse date from git stream.")
			}
			currentCommit.Date = date
		case isDiffLine(line):
			// This should never be nil, but check in case the stdin stream is messed up.
			if currentCommit == nil {
				currentCommit = &Commit{}
			}
			if currentDiff != nil && currentDiff.Content.Len() > 0 {
				currentCommit.Diffs = append(currentCommit.Diffs, *currentDiff)
			}
			currentDiff = &Diff{}
		case isModeLine(line):
			// NoOp
		case isIndexLine(line):
			// NoOp
		case isPlusFileLine(line):
			currentDiff.PathB = strings.TrimRight(string(line[6:]), "\n")
		case isMinusFileLine(line):
			// NoOp
		case isPlusDiffLine(line):
			currentDiff.Content.Write(line[1:])
		case isMinusDiffLine(line):
			// NoOp. We only care about additions.
		case isMessageLine(line):
			currentCommit.Message.Write(line[4:])
		case isContextDiffLine(line):
			currentDiff.Content.Write([]byte("\n"))
		case isBinaryLine(line):
			currentDiff.IsBinary = true
			currentDiff.PathB = pathFromBinaryLine(line)
		case isLineNumberDiffLine(line):
			if currentDiff != nil && currentDiff.Content.Len() > 0 {
				currentCommit.Diffs = append(currentCommit.Diffs, *currentDiff)
			}
			newDiff := &Diff{
				PathB: currentDiff.PathB,
			}

			currentDiff = newDiff

			words := bytes.Split(line, []byte(" "))
			if len(words) >= 3 {
				startSlice := bytes.Split(words[2], []byte(","))
				lineStart, err := strconv.Atoi(string(startSlice[0]))
				if err == nil {
					currentDiff.LineStart = lineStart
				}
			}
		}

	}
	if currentDiff != nil && currentDiff.Content.Len() > 0 {
		currentCommit.Diffs = append(currentCommit.Diffs, *currentDiff)
	}
	if currentCommit != nil {
		commitChan <- *currentCommit
	}
	close(commitChan)
}

// Date:   Tue Aug 10 15:20:40 2021 +0100
func isDateLine(line []byte) bool {
	if len(line) > 7 && bytes.Equal(line[:5], []byte("Date:")) {
		return true
	}
	return false
}

// Author: Bill Rich <bill.rich@trufflesec.com>
func isAuthorLine(line []byte) bool {
	if len(line) > 8 && bytes.Equal(line[:7], []byte("Author:")) {
		return true
	}
	return false
}

// commit 7a95bbf0199e280a0e42dbb1d1a3f56cdd0f6e05
func isCommitLine(line []byte) bool {
	if len(line) > 7 && bytes.Equal(line[:6], []byte("commit")) {
		return true
	}
	return false
}

// diff --git a/internal/addrs/move_endpoint_module.go b/internal/addrs/move_endpoint_module.go
func isDiffLine(line []byte) bool {
	if len(line) > 5 && bytes.Equal(line[:4], []byte("diff")) {
		return true
	}
	return false
}

// index 1ed6fbee1..aea1e643a 100644
func isIndexLine(line []byte) bool {
	if len(line) > 6 && bytes.Equal(line[:5], []byte("index")) {
		return true
	}
	return false
}

// new file mode 100644
func isModeLine(line []byte) bool {
	if len(line) > 13 && bytes.Equal(line[:13], []byte("new file mode")) {
		return true
	}
	return false
}

// --- a/internal/addrs/move_endpoint_module.go
func isMinusFileLine(line []byte) bool {
	if len(line) >= 6 && bytes.Equal(line[:3], []byte("---")) {
		return true
	}
	return false
}

// +++ b/internal/addrs/move_endpoint_module.go
func isPlusFileLine(line []byte) bool {
	if len(line) >= 6 && bytes.Equal(line[:3], []byte("+++")) {
		return true
	}
	return false
}

// +fmt.Println("ok")
func isPlusDiffLine(line []byte) bool {
	if len(line) >= 1 && bytes.Equal(line[:1], []byte("+")) {
		return true
	}
	return false
}

// -fmt.Println("ok")
func isMinusDiffLine(line []byte) bool {
	if len(line) >= 1 && bytes.Equal(line[:1], []byte("-")) {
		return true
	}
	return false
}

// fmt.Println("ok")
func isContextDiffLine(line []byte) bool {
	if len(line) >= 1 && bytes.Equal(line[:1], []byte(" ")) {
		return true
	}
	return false
}

// Line that starts with 4 spaces
func isMessageLine(line []byte) bool {
	if len(line) > 4 && bytes.Equal(line[:4], []byte("    ")) {
		return true
	}
	return false
}

// Binary files /dev/null and b/plugin.sig differ
func isBinaryLine(line []byte) bool {
	if len(line) > 7 && bytes.Equal(line[:6], []byte("Binary")) {
		return true
	}
	return false
}

// @@ -298 +298 @@ func maxRetryErrorHandler(resp *http.Response, err error, numTries int)
func isLineNumberDiffLine(line []byte) bool {
	if len(line) >= 8 && bytes.Equal(line[:2], []byte("@@")) {
		return true
	}
	return false
}

// Get the b/ file path.
func pathFromBinaryLine(line []byte) string {
	sbytes := bytes.Split(line, []byte(" and "))
	if len(sbytes) != 2 {
		log.Debugf("Expected binary line to be in 'Binary files a/filaA and b/fileB differ' format. Got: %s", line)
		return ""
	}
	bRaw := sbytes[1]
	return string(bRaw[2 : len(bRaw)-7]) // drop the "b/" and " differ"
}
