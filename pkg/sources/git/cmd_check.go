package git

import (
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/go-errors/errors"
)

// Extract the version string using a regex to find the major and minor numbers.
// Only the major and minor components are needed for the version check, and some
// builds report a non-numeric patch component (for example "2.52.gaea8cc3"), so
// matching the full "x.y.z" form here would fail to find a match for them.
var regex = regexp.MustCompile(`\d+\.\d+`)

// CmdCheck checks if git is installed and meets 2.20.0<=x<3.0.0 version requirements.
func CmdCheck() error {
	if errors.Is(exec.Command("git").Run(), exec.ErrNotFound) {
		return fmt.Errorf("'git' command not found in $PATH. Make sure git is installed and included in $PATH")
	}

	// Check the version is greater than or equal to 2.20.0
	out, err := exec.Command("git", "--version").Output()
	if err != nil {
		return fmt.Errorf("failed to check git version: %w", err)
	}

	return checkGitVersion(string(out))
}

// checkGitVersion verifies that the output of `git --version` reports a version
// in the range 2.20.0 <= x < 3.0.0.
func checkGitVersion(version string) error {
	versionStr := regex.FindString(version)
	versionParts := strings.Split(versionStr, ".")
	if len(versionParts) < 2 {
		return fmt.Errorf("could not parse git version from %q", strings.TrimSpace(version))
	}

	// Parse version numbers
	major, _ := strconv.Atoi(versionParts[0])
	minor, _ := strconv.Atoi(versionParts[1])

	// Compare with version 2.20.0<=x<3.0.0
	if major == 2 && minor >= 20 {
		return nil
	}
	return fmt.Errorf("git version is %s, but must be greater than or equal to 2.20.0, and less than 3.0.0", versionStr)
}
