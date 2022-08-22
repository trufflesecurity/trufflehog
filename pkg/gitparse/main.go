//package main
package gitparse

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
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
	PathA     string
	PathB     string
	LineStart int
	Content   bytes.Buffer
	IsBinary  bool
}

/*
func main() {
	source := "/home/hrich/go/src/github.com/hashicorp/terraform"
	start := time.Now()
	fileChan := BillParser(source)
	for range fileChan {
	}
	newTime := time.Now().Sub(start)

	start = time.Now()
	errChan := make(chan error)
	fileChan2, _ := glgo.GitLog(source, glgo.LogOpts{}, errChan)
	for range fileChan2 {
	}
	oldTime := time.Now().Sub(start)

	fmt.Printf("Gitleaks parser: %d seconds\nNew parser: %d seconds", oldTime.Seconds(), newTime.Seconds())

}
*/

func BillParser(source string) chan Commit {
	cmd := exec.Command("git", "-C", source, "log", "-p", "-U0", "--full-history", "--all", "--diff-filter=AM", "--date=format:%a %b %d %H:%M:%S %Y %z")

	stdOut, err := cmd.StdoutPipe()
	if err != nil {
		errs(err)
	}
	// TODO: Handle errors
	// stdErr, err := cmd.StderrPipe()
	// if err != nil {
	// 	errs(err)
	// }

	err = cmd.Start()
	if err != nil {
		errs(err)
	}

	outReader := bufio.NewReader(stdOut)
	var currentCommit *Commit
	var currentDiff *Diff

	commitChan := make(chan Commit)

	// TODO: Something about nil handling maybe? I don't remember
	go func() {
		for {
			line, _, err := outReader.ReadLine()
			if err != nil {
				fmt.Println(err)
				break
			}
			logrus.Debugf("Line: %s", line)
			switch {
			case isCommitLine(line):
				logrus.Debugf("commitline: %s", line)
				if currentCommit != nil {
					commitChan <- *currentCommit
				}
				currentCommit = &Commit{
					Message: strings.Builder{},
				}
				currentCommit.Hash = string(line[7:])
			case isAuthorLine(line):
				currentCommit.Author = string(line[8:])
			case isDateLine(line):
				date, err := time.Parse(DateFormat, strings.TrimSpace(string(line[6:])))
				if err != nil {
					errs(err)
				}
				currentCommit.Date = date
			case isDiffLine(line):
				if currentDiff != nil {
					currentCommit.Diffs = append(currentCommit.Diffs, *currentDiff)
				}
				currentDiff = &Diff{}
			case isModeLine(line):
			case isIndexLine(line):
			case isPlusFileLine(line):
				currentDiff.PathB = string(line[4:])
			case isMinusFileLine(line):
				currentDiff.PathA = string(line[4:])
			case isPlusDiffLine(line):
				currentDiff.Content.Write(line[1:])
				currentDiff.Content.Write([]byte("\n"))
			case isMinusDiffLine(line):
			case isMessageLine(line):
				currentCommit.Message.Write(line[4:])
			case isBinaryLine(line):
				currentDiff.IsBinary = true
				currentDiff.PathB = pathFromBinaryLine(line, source)
			}

		}
		if currentDiff != nil && currentDiff.Content.Len() > 0 {
			currentCommit.Diffs = append(currentCommit.Diffs, *currentDiff)
		}
		if currentCommit != nil {
			commitChan <- *currentCommit
		}
		cmd.Wait()
		close(commitChan)
	}()
	return commitChan
}

func isDateLine(line []byte) bool {
	if len(line) > 7 && bytes.Equal(line[:5], []byte("Date:")) {
		return true
	}
	return false
}

func isAuthorLine(line []byte) bool {
	if len(line) > 8 && bytes.Equal(line[:7], []byte("Author:")) {
		return true
	}
	return false
}

func isCommitLine(line []byte) bool {
	if len(line) > 7 && bytes.Equal(line[:6], []byte("commit")) {
		return true
	}
	return false
}

func isDiffLine(line []byte) bool {
	if len(line) > 5 && bytes.Equal(line[:4], []byte("diff")) {
		return true
	}
	return false
}

func isIndexLine(line []byte) bool {
	if len(line) > 6 && bytes.Equal(line[:5], []byte("index")) {
		return true
	}
	return false
}

func isModeLine(line []byte) bool {
	if len(line) > 8 && bytes.Equal(line[:8], []byte("new mode")) {
		return true
	}
	return false
}

func isMinusFileLine(line []byte) bool {
	if len(line) > 3 && bytes.Equal(line[:3], []byte("---")) {
		return true
	}
	return false
}

func isPlusFileLine(line []byte) bool {
	if len(line) > 3 && bytes.Equal(line[:3], []byte("+++")) {
		return true
	}
	return false
}

func isPlusDiffLine(line []byte) bool {
	if len(line) > 1 && bytes.Equal(line[:1], []byte("+")) {
		return true
	}
	return false
}

func isMinusDiffLine(line []byte) bool {
	if len(line) > 1 && bytes.Equal(line[:1], []byte("-")) {
		return true
	}
	return false
}

func isMessageLine(line []byte) bool {
	if len(line) > 4 && bytes.Equal(line[:4], []byte("    ")) {
		return true
	}
	return false
}

func isBinaryLine(line []byte) bool {
	if len(line) > 7 && bytes.Equal(line[:6], []byte("Binary")) {
		return true
	}
	return false
}

func pathFromBinaryLine(line []byte, source string) string {
	sbytes := bytes.Split(line, []byte(" and "))
	if len(sbytes) != 2 {
		logrus.Errorf("Expected binary line to be in 'Binary files a/filaA and b/fileB differ' format. Got: %s", line)
		return ""
	}
	bRaw := sbytes[1]
	return string(bRaw[2 : len(bRaw)-7]) // drop the "b/" and " differ"
}

func errs(err error) {
	log.Println(err)
}
