// Package gitcmd provides helpers for interacting with the local git binary.
package gitcmd

import (
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/go-errors/errors"
)

// gitVersionRegex captures the major and minor numbers from `git --version` output.
// We intentionally do not capture the patch version: git built from source can report
// a non-numeric patch like "git version 2.52.gaea8cc3", and the patch is unused here.
var gitVersionRegex = regexp.MustCompile(`(\d+)\.(\d+)`)

// CheckVersion checks if git is installed and meets 2.20.0<=x<3.0.0 version requirements.
func CheckVersion() error {
	if errors.Is(exec.Command("git").Run(), exec.ErrNotFound) {
		return fmt.Errorf("'git' command not found in $PATH. Make sure git is installed and included in $PATH")
	}

	// Check the version is greater than or equal to 2.20.0
	out, err := exec.Command("git", "--version").Output()
	if err != nil {
		return fmt.Errorf("failed to check git version: %w", err)
	}

	major, minor, err := parseGitVersion(string(out))
	if err != nil {
		return err
	}

	// Compare with version 2.20.0<=x<3.0.0
	if major == 2 && minor >= 20 {
		return nil
	}
	return fmt.Errorf("git version is %d.%d, but must be greater than or equal to 2.20.0, and less than 3.0.0", major, minor)
}

// parseGitVersion extracts the major and minor numbers from `git --version` output.
func parseGitVersion(out string) (major, minor int, err error) {
	matches := gitVersionRegex.FindStringSubmatch(out)
	if len(matches) < 3 {
		return 0, 0, fmt.Errorf("failed to parse git version from %q", strings.TrimSpace(out))
	}
	// Errors are impossible here since the regex only matches digits.
	major, _ = strconv.Atoi(matches[1])
	minor, _ = strconv.Atoi(matches[2])
	return major, minor, nil
}
